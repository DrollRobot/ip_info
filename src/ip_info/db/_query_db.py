import ipaddress
import sqlite3
import sys
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from ip_info.config import (
    IP_TABLE_NAME,
    LOCAL_TIMEZONE,
    MAX_AGE,
    MAX_RATE_LIMIT_WAIT,
    QUERY_TABLE_NAME,
)


def _rolling_window(timeframe: str) -> timedelta:
    """Return the rolling-window length for a rate-limit timeframe."""
    windows = {
        "second": timedelta(seconds=1),
        "minute": timedelta(minutes=1),
        "hour": timedelta(hours=1),
        "day": timedelta(days=1),
        "month": timedelta(days=30),
    }
    try:
        return windows[timeframe]
    except KeyError:
        raise ValueError(f"Unknown timeframe: {timeframe!r}") from None


def _absolute_window(now: datetime, timeframe: str) -> tuple[datetime, datetime]:
    """Return the [start, end) bounds of the absolute window containing now."""
    if timeframe == "second":
        start = now.replace(microsecond=0)
        end = start + timedelta(seconds=1)
    elif timeframe == "minute":
        start = now.replace(second=0, microsecond=0)
        end = start + timedelta(minutes=1)
    elif timeframe == "hour":
        start = now.replace(minute=0, second=0, microsecond=0)
        end = start + timedelta(hours=1)
    elif timeframe == "day":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
    elif timeframe == "month":
        start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if now.month == 12:
            end = start.replace(year=now.year + 1, month=1)
        else:
            end = start.replace(month=now.month + 1)
    else:
        raise ValueError(f"Unknown timeframe: {timeframe!r}")
    return start, end


def _matching_error_rows(
    rows: list[dict[str, Any]], status_code: int | None, error_text: str | None
) -> list[dict[str, Any]]:
    """Return rows whose response signals that the provider's rate limit was hit."""
    if status_code is None:
        return []
    matching = [row for row in rows if row["status_code"] == status_code]
    if error_text:
        matching = [row for row in matching if error_text in (row["error_text"] or "")]
    return matching


def _check_rate_limits(
    api_name: str, rate_limits: list[dict[str, Any]], db_conn: sqlite3.Connection
) -> datetime:
    """Compute the earliest time a query for api_name satisfies every rate limit.

    Accepts rate_limits dict. Should have one entry for each type of rate limit the
    provider has. (per second, per hour, daily, monthly, etc...)

    rolling - Indicates a rolling limit. For example, with a daily rolling limit,
    queries from the last 24 hours are looked at.

    absolute - Indicates a limit that starts at the beginning of a whole period. For
    example, an absolute daily limit means the counter starts at 12:00am and ends at
    11:59pm.

    status_code,error_text - If a query returns this status code(and error_text if
    present), it means the rate limit has been reached. No further queries until that
    response leaves the window.

    rate_limits = [
        {
            "query_limit": 4,
            "timeframe":   "minute",
            "type":        "rolling",
            "status_code": 429
        },
        {
            "query_limit": 1000,
            "timeframe":   "day",
            "type":        "absolute",
            "status_code": 429,
            "error_text":  "Too Many Requests"
        },
    ]

    A limit is considered reached when the window already holds query_limit calls
    (at most query_limit calls per window). This function never sleeps; waiting is
    the caller's responsibility (see _respect_rate_limit).

    Returns:
      A timezone-aware datetime in LOCAL_TIMEZONE. A value at or before the current
      time means the query may proceed immediately; a future value is the earliest
      instant at which every configured limit is satisfied.
    """
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    def _dict_factory(cursor: sqlite3.Cursor, row: tuple[Any, ...]) -> dict[str, Any]:
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

    # pull all table entries for this api_name
    db_conn.row_factory = _dict_factory
    cursor = db_conn.cursor()
    # table/column identifiers are internal constants; values are parameterized
    cursor.execute(
        f"""
        SELECT *
        FROM {QUERY_TABLE_NAME}
        WHERE api_name = ?
        ORDER BY timestamp
        """,  # noqa: S608
        (api_name,),
    )
    rows = cursor.fetchall()

    now = datetime.now(LOCAL_TIMEZONE)
    free_times: list[datetime] = [now]

    for rate_limit in rate_limits:
        query_limit = rate_limit["query_limit"]
        timeframe = rate_limit["timeframe"]
        mode = rate_limit.get("type", "rolling")
        status_code = rate_limit.get("status_code")
        error_text = rate_limit.get("error_text")

        if mode == "rolling":
            window = _rolling_window(timeframe)
            cutoff = now - window
            timeframe_rows = [row for row in rows if row["timestamp"] >= cutoff]

            if len(timeframe_rows) >= query_limit:
                # free when enough of the oldest in-window calls age out that the
                # window holds query_limit - 1 of them
                timestamps = sorted(row["timestamp"] for row in timeframe_rows)
                free_times.append(timestamps[len(timestamps) - query_limit] + window)

            error_rows = _matching_error_rows(timeframe_rows, status_code, error_text)
            if error_rows:
                # blocked until the newest rate-limit response leaves the window
                free_times.append(max(row["timestamp"] for row in error_rows) + window)

        elif mode == "absolute":
            start, end = _absolute_window(now, timeframe)
            timeframe_rows = [row for row in rows if start <= row["timestamp"] < end]

            if len(timeframe_rows) >= query_limit:
                free_times.append(end)

            if _matching_error_rows(timeframe_rows, status_code, error_text):
                free_times.append(end)

        else:
            raise ValueError(f"type must be 'rolling' or 'absolute', got {mode!r}")

    return max(free_times)


def _respect_rate_limit(
    api_name: str,
    api_display_name: str,
    rate_limits: list[dict[str, Any]],
    db_conn: sqlite3.Connection,
) -> bool:
    """Wait until the next allowed query time, or report that the query should be skipped.

    Sleeps until _check_rate_limits allows a query, as long as the wait is at most
    MAX_RATE_LIMIT_WAIT seconds.

    Returns:
      True - Next allowed time is too far away. Skip the query.
      False - Clear to query now (after sleeping, if a short wait was needed).
    """
    allowed_at = _check_rate_limits(api_name, rate_limits, db_conn)
    wait = (allowed_at - datetime.now(LOCAL_TIMEZONE)).total_seconds()
    if wait <= 0:
        return False
    if wait <= MAX_RATE_LIMIT_WAIT:
        print(f"Rate limit reached for {api_display_name}. Waiting {wait:.1f}s...")
        time.sleep(wait)
        return False
    print(f"Rate limit reached for {api_display_name}. Next slot in {wait:.0f}s; skipping.")
    return True


def _fetch_ip_info(
    *,
    api_names: list[str],
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    db_conn: sqlite3.Connection,
) -> list[dict[str, Any]]:
    """Fetch stored responses for given API names and IP address.

    If api_names is 'all', returns all records for that IP_address.
    Returns a list of dicts.
    """
    # build query
    if api_names == ["all"]:
        query = (
            # table/column identifiers are internal constants; values are parameterized
            f"SELECT * FROM {IP_TABLE_NAME} "  # noqa: S608
            "WHERE ip_address = ?"
        )
        params = [str(ip_address)]
    else:
        placeholders = ", ".join("?" for _ in api_names)
        query = (
            # table/column identifiers are internal constants; values are parameterized
            f"SELECT * FROM {IP_TABLE_NAME} "  # noqa: S608
            f"WHERE api_name IN ({placeholders}) "
            "AND ip_address = ?"
        )
        params = [*api_names, str(ip_address)]

    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    db_conn.row_factory = sqlite3.Row
    cursor = db_conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()

    return [dict(row) for row in rows]


def _is_db_entry_recent(
    api_name: str,
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    db_conn: sqlite3.Connection,
    max_age: int = MAX_AGE,
) -> bool:
    """Check if a database entry for the specified API and IP address is recent.

    Returns True if at least one entry is within max_age days.
    """
    # reuse _fetch_ip_info, passing along db_conn
    entries = _fetch_ip_info(api_names=[api_name], ip_address=ip_address, db_conn=db_conn)
    if not entries:
        return False

    first_ts = entries[0]["timestamp"]
    tz = first_ts.tzinfo or UTC
    now = datetime.now(tz)
    cutoff = now - timedelta(days=max_age)

    return any(entry.get("timestamp") and entry["timestamp"] >= cutoff for entry in entries)
