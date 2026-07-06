"""Tests for the rate-limit datetime contract and the wait-or-skip helper."""

import sqlite3
import time
from datetime import datetime, timedelta

import pytest

from ip_info.config import LOCAL_TIMEZONE, MAX_RATE_LIMIT_WAIT
from ip_info.db import _query_db
from ip_info.db._query_db import (
    _absolute_window,
    _check_rate_limits,
    _respect_rate_limit,
    _rolling_window,
)

API = "demo"


def _ts(seconds_ago: float) -> datetime:
    """Return a timezone-aware timestamp *seconds_ago* seconds in the past."""
    return datetime.now(LOCAL_TIMEZONE) - timedelta(seconds=seconds_ago)


def _insert_query(
    db_conn: sqlite3.Connection,
    timestamp: datetime,
    status_code: int = 200,
    error_text: str | None = "",
) -> None:
    """Insert one fake query-log row for the demo API at *timestamp*."""
    cur = db_conn.cursor()
    cur.execute(
        "INSERT INTO api_queries (api_name,timestamp,status_code,error_text) VALUES (?,?,?,?)",
        (API, timestamp, status_code, error_text),
    )
    db_conn.commit()


@pytest.mark.parametrize(
    ("timeframe", "expected"),
    [
        ("second", timedelta(seconds=1)),
        ("minute", timedelta(minutes=1)),
        ("hour", timedelta(hours=1)),
        ("day", timedelta(days=1)),
        ("month", timedelta(days=30)),
    ],
)
def test_rolling_window_lengths(timeframe: str, expected: timedelta) -> None:
    """Each rolling timeframe maps to its window length."""
    assert _rolling_window(timeframe) == expected


def test_rolling_window_unknown_timeframe_raises() -> None:
    """An unknown rolling timeframe fails loudly."""
    with pytest.raises(ValueError, match="Unknown timeframe"):
        _rolling_window("fortnight")


@pytest.mark.parametrize(
    ("timeframe", "expected_start", "expected_end"),
    [
        (
            "second",
            datetime(2026, 7, 6, 15, 30, 45, tzinfo=LOCAL_TIMEZONE),
            datetime(2026, 7, 6, 15, 30, 46, tzinfo=LOCAL_TIMEZONE),
        ),
        (
            "minute",
            datetime(2026, 7, 6, 15, 30, tzinfo=LOCAL_TIMEZONE),
            datetime(2026, 7, 6, 15, 31, tzinfo=LOCAL_TIMEZONE),
        ),
        (
            "hour",
            datetime(2026, 7, 6, 15, tzinfo=LOCAL_TIMEZONE),
            datetime(2026, 7, 6, 16, tzinfo=LOCAL_TIMEZONE),
        ),
        (
            "day",
            datetime(2026, 7, 6, tzinfo=LOCAL_TIMEZONE),
            datetime(2026, 7, 7, tzinfo=LOCAL_TIMEZONE),
        ),
        (
            "month",
            datetime(2026, 7, 1, tzinfo=LOCAL_TIMEZONE),
            datetime(2026, 8, 1, tzinfo=LOCAL_TIMEZONE),
        ),
    ],
)
def test_absolute_window_bounds(
    timeframe: str, expected_start: datetime, expected_end: datetime
) -> None:
    """Each absolute timeframe maps to the [start, end) bounds containing now."""
    now = datetime(2026, 7, 6, 15, 30, 45, 123456, tzinfo=LOCAL_TIMEZONE)
    assert _absolute_window(now, timeframe) == (expected_start, expected_end)


def test_absolute_window_month_year_rollover() -> None:
    """A December monthly window ends on January 1st of the next year."""
    now = datetime(2026, 12, 15, 8, 0, tzinfo=LOCAL_TIMEZONE)
    start, end = _absolute_window(now, "month")
    assert start == datetime(2026, 12, 1, tzinfo=LOCAL_TIMEZONE)
    assert end == datetime(2027, 1, 1, tzinfo=LOCAL_TIMEZONE)


def test_absolute_window_unknown_timeframe_raises() -> None:
    """An unknown absolute timeframe fails loudly."""
    now = datetime(2026, 7, 6, tzinfo=LOCAL_TIMEZONE)
    with pytest.raises(ValueError, match="Unknown timeframe"):
        _absolute_window(now, "fortnight")


def test_under_limit_allows_now(db_conn: sqlite3.Connection) -> None:
    """Fewer in-window calls than the limit permits a query immediately."""
    rate_limits = [{"query_limit": 3, "timeframe": "minute", "type": "rolling"}]
    _insert_query(db_conn, _ts(10))
    _insert_query(db_conn, _ts(5))

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    assert allowed_at <= datetime.now(LOCAL_TIMEZONE)


def test_no_rate_limits_allows_now(db_conn: sqlite3.Connection) -> None:
    """An empty rate_limits list never blocks."""
    _insert_query(db_conn, _ts(0))

    allowed_at = _check_rate_limits(API, [], db_conn)

    assert allowed_at <= datetime.now(LOCAL_TIMEZONE)


def test_rolling_second_at_limit(db_conn: sqlite3.Connection) -> None:
    """Hitting a rolling per-second limit frees up when the oldest call ages out."""
    rate_limits = [{"query_limit": 2, "timeframe": "second", "type": "rolling"}]
    oldest = _ts(0)
    _insert_query(db_conn, oldest)
    _insert_query(db_conn, _ts(0))

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    assert allowed_at == oldest + timedelta(seconds=1)


def test_rolling_over_limit_by_more_than_one(db_conn: sqlite3.Connection) -> None:
    """With count > limit, the wait ends when enough of the oldest calls age out."""
    rate_limits = [{"query_limit": 2, "timeframe": "minute", "type": "rolling"}]
    second_oldest = _ts(30)
    _insert_query(db_conn, _ts(40))
    _insert_query(db_conn, second_oldest)
    _insert_query(db_conn, _ts(10))

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    # timestamps[count - limit] = timestamps[1]; free once it leaves the window
    assert allowed_at == second_oldest + timedelta(minutes=1)


def test_absolute_over_limit_returns_window_end(db_conn: sqlite3.Connection) -> None:
    """Hitting an absolute daily limit blocks until the next day boundary."""
    rate_limits = [{"query_limit": 2, "timeframe": "day", "type": "absolute"}]
    _insert_query(db_conn, _ts(1))
    _insert_query(db_conn, _ts(0))

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    now = datetime.now(LOCAL_TIMEZONE)
    expected_end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    assert allowed_at == expected_end


def test_provider_signalled_limit_blocks_until_window_clears(
    db_conn: sqlite3.Connection,
) -> None:
    """A stored rate-limit response blocks until it leaves the rolling window."""
    rate_limits = [
        {
            "query_limit": 100,
            "timeframe": "minute",
            "type": "rolling",
            "status_code": 429,
            "error_text": "Too many requests",
        }
    ]
    limited_at = _ts(30)
    _insert_query(db_conn, limited_at, status_code=429, error_text="Too many requests received")

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    assert allowed_at == limited_at + timedelta(minutes=1)


def test_provider_signalled_limit_absolute_blocks_until_window_end(
    db_conn: sqlite3.Connection,
) -> None:
    """A stored rate-limit response in an absolute window blocks until its boundary."""
    rate_limits = [
        {
            "query_limit": 1000,
            "timeframe": "day",
            "type": "absolute",
            "status_code": 429,
            "error_text": "Too many requests",
        }
    ]
    _insert_query(db_conn, _ts(60), status_code=429, error_text="Too many requests")

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    now = datetime.now(LOCAL_TIMEZONE)
    expected_end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    assert allowed_at == expected_end


def test_provider_signalled_error_text_mismatch_allows(db_conn: sqlite3.Connection) -> None:
    """A matching status code with non-matching error text does not block."""
    rate_limits = [
        {
            "query_limit": 100,
            "timeframe": "minute",
            "type": "rolling",
            "status_code": 429,
            "error_text": "Too many requests",
        }
    ]
    _insert_query(db_conn, _ts(30), status_code=429, error_text="unrelated failure")
    # a NULL error_text must not match (or crash) either
    _insert_query(db_conn, _ts(20), status_code=429, error_text=None)

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    assert allowed_at <= datetime.now(LOCAL_TIMEZONE)


def test_multiple_limits_returns_latest_free_time(db_conn: sqlite3.Connection) -> None:
    """With several limits hit, the result satisfies every limit (max of all)."""
    rate_limits = [
        {"query_limit": 1, "timeframe": "second", "type": "rolling"},
        {"query_limit": 1, "timeframe": "day", "type": "absolute"},
    ]
    _insert_query(db_conn, _ts(0))

    allowed_at = _check_rate_limits(API, rate_limits, db_conn)

    now = datetime.now(LOCAL_TIMEZONE)
    expected_end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    assert allowed_at == expected_end


def test_unknown_timeframe_raises(db_conn: sqlite3.Connection) -> None:
    """An unknown timeframe fails loudly."""
    rate_limits = [{"query_limit": 1, "timeframe": "fortnight", "type": "rolling"}]

    with pytest.raises(ValueError, match="Unknown timeframe"):
        _check_rate_limits(API, rate_limits, db_conn)


def test_unknown_mode_raises(db_conn: sqlite3.Connection) -> None:
    """An unknown limit type fails loudly."""
    rate_limits = [{"query_limit": 1, "timeframe": "day", "type": "sliding"}]

    with pytest.raises(ValueError, match=r"rolling.*absolute"):
        _check_rate_limits(API, rate_limits, db_conn)


def test_respect_rate_limit_proceeds_immediately(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A next-allowed time in the past proceeds without sleeping."""
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", slept.append)
    monkeypatch.setattr(
        _query_db,
        "_check_rate_limits",
        lambda *args: datetime.now(LOCAL_TIMEZONE) - timedelta(seconds=10),
    )

    assert _respect_rate_limit(API, "Demo", [], db_conn) is False
    assert slept == []


def test_respect_rate_limit_waits_for_short_delays(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wait within MAX_RATE_LIMIT_WAIT sleeps until the allowed time, then proceeds."""
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", slept.append)
    monkeypatch.setattr(
        _query_db,
        "_check_rate_limits",
        lambda *args: datetime.now(LOCAL_TIMEZONE) + timedelta(seconds=MAX_RATE_LIMIT_WAIT),
    )

    assert _respect_rate_limit(API, "Demo", [], db_conn) is False
    assert len(slept) == 1
    assert 0 < slept[0] <= MAX_RATE_LIMIT_WAIT


def test_respect_rate_limit_skips_long_delays(
    db_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wait beyond MAX_RATE_LIMIT_WAIT skips the query without sleeping."""
    slept: list[float] = []
    monkeypatch.setattr(time, "sleep", slept.append)
    monkeypatch.setattr(
        _query_db,
        "_check_rate_limits",
        lambda *args: datetime.now(LOCAL_TIMEZONE) + timedelta(seconds=MAX_RATE_LIMIT_WAIT + 60),
    )

    assert _respect_rate_limit(API, "Demo", [], db_conn) is True
    assert slept == []
