from datetime import datetime, timedelta, timezone
import sqlite3
import sys
import time
from typing import Any

from ip_info.config import IP_TABLE_NAME, LOCAL_TIMEZONE, MAX_AGE, QUERY_TABLE_NAME


def _check_rate_limits(
    api_name: str,
    rate_limits: list[dict],
    db_conn: sqlite3.Connection
):
    """
    Enforce rate_limits for api_name, supporting 'rolling' or 'absolute' windows.

    Accepts rate_limits dict. Should have one entry for each type of rate limit the 
    provider has. (per second, per hour, daily, monthly, etc...)

    rolling - Indicates a rolling limit. For example, with a daily rolling limit,
    queries from the last 24 hours are looked at. 

    absolute - Indicates a limit that starts at the beginning of a whole period. For
    example, an absolute daily limit means the counter starts at 12:00am and ends at
    11:59pm. 

    status_code,error_text - If a query returns this status code(and error_text if 
    present), it means the rate limit has been reached. No further queries for the given 
    time period.

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

    Returns:
      True - Rate limit reached. Do not query.
      False - No rate limit reached. Proceed with query.
    """
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")
    
    def _dict_factory(cursor, row):
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}

    # pull all table entries for this api_name
    db_conn.row_factory = _dict_factory
    cursor = db_conn.cursor()
    cursor.execute(
        f"""
        SELECT *
        FROM {QUERY_TABLE_NAME}
        WHERE api_name = ?
        ORDER BY timestamp
        """,
        (api_name,)
    )
    rows = cursor.fetchall()

    now = datetime.now(LOCAL_TIMEZONE)

    for rate_limit in rate_limits:

        query_limit = rate_limit["query_limit"]
        timeframe = rate_limit["timeframe"]
        mode = rate_limit.get("type", "rolling")
        status_code = rate_limit.get("status_code")
        error_text = rate_limit.get("error_text")
        limit_text = f"{query_limit}/{timeframe}"

        # build window starting from current time
        if mode == "rolling":
            if timeframe == "second":
                window = timedelta(seconds=1)
            elif timeframe == "minute":
                window = timedelta(minutes=1)
            elif timeframe == "hour":
                window = timedelta(hours=1)
            elif timeframe == "day":
                window = timedelta(days=1)
            elif timeframe == "month":
                window = timedelta(days=30)
            else:
                raise ValueError(f"Unknown timeframe: {timeframe!r}")
            
            cutoff = now - window
            timeframe_rows = [row for row in rows if row["timestamp"] >= cutoff]

        # build window from start to end of current second/minute/day/etc...
        elif mode == "absolute":
            if timeframe == "second":
                start = now.replace(microsecond=0)
                end   = start + timedelta(seconds=1)
            elif timeframe == "minute":
                start = now.replace(second=0, microsecond=0)
                end   = start + timedelta(minutes=1)
            elif timeframe == "hour":
                start = now.replace(minute=0, second=0, microsecond=0)
                end   = start + timedelta(hours=1)
            elif timeframe == "day":
                start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                end   = start + timedelta(days=1)
            elif timeframe == "month":
                start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                if now.month == 12:
                    end = start.replace(year=now.year+1, month=1)
                else:
                    end = start.replace(month=now.month+1)
            else:
                raise ValueError(f"Unknown timeframe: {timeframe!r}")

            timeframe_rows = [row for row in rows if start <= row["timestamp"] < end] # FIXME

        else:
            raise ValueError(f"type must be 'rolling' or 'absolute', got {mode!r}")

        # if query limit exceeded
        if len(timeframe_rows) >= query_limit:
            # if seconds, wait until next second and return true
            if timeframe == "second":
                # compute sleep duration
                if mode == "rolling":
                    earliest_ts = min(row["timestamp"] for row in timeframe_rows)
                    wake_at   = earliest_ts + timedelta(seconds=1)
                else:  # absolute: wake at next boundary
                    wake_at = end # type: ignore
                wait = (wake_at - now).total_seconds()
                if wait > 0:
                    time.sleep(wait)
                query_check =  True
            # if anything other than seconds, return false
            else:
                print(f"{api_name} limit hit: {limit_text}")
                query_check = False
        # if query limit not exceeded, return true
        else:
            query_check = True

        # check if error message found
        status_code_rows = [row for row in timeframe_rows if row["status_code"] == status_code]
        if status_code_rows:
            if error_text:
                error_check = any(error_text in row["error_text"] for row in status_code_rows)
                error_check = not error_check
            else:
                error_check = False
        # return true if no queries match
        else:
            error_check = True

        # if both tests true, return False to allow query
        if query_check and error_check:
            return False
        # if either test failed, return True to prevent query
        else:
            return True
        

def _fetch_ip_info(api_names, ip_address, db_conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """
    Fetches stored responses for given API names and IP address.
    If api_names is 'all', returns all records for that IP_address.
    Returns a list of dicts.
    """
    # normalize to list
    if isinstance(api_names, str):
        api_names = [api_names]

    # build query
    if api_names == ["all"]:
        # ignore api_name filter
        query = (
            f"SELECT * FROM {IP_TABLE_NAME} "
            "WHERE ip_address = ?"
        )
        params = [ip_address]
    else:
        placeholders = ", ".join("?" for _ in api_names)
        query = (
            f"SELECT * FROM {IP_TABLE_NAME} "
            f"WHERE api_name IN ({placeholders}) "
            "AND ip_address = ?"
        )
        params = api_names + [ip_address]

    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    db_conn.row_factory = sqlite3.Row
    cursor = db_conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()

    return [dict(row) for row in rows]


def _is_db_entry_recent(api_name, ip_address, db_conn: sqlite3.Connection, max_age=MAX_AGE):
    """
    Checks if a database entry for the specified API and IP address is recent.
    Returns True if at least one entry is within max_age days.
    """
    # reuse _fetch_ip_info, passing along db_conn
    entries = _fetch_ip_info(api_name, ip_address, db_conn=db_conn)
    if not entries:
        return False

    first_ts = entries[0]["timestamp"]
    tz = first_ts.tzinfo or timezone.utc 
    now = datetime.now(tz)
    cutoff = now - timedelta(days=max_age)

    return any(
        entry.get("timestamp") and entry["timestamp"] >= cutoff
        for entry in entries
    )
