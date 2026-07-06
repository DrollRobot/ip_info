import sqlite3
from datetime import datetime, timedelta

from ip_info.config import LOCAL_TIMEZONE
from ip_info.db._query_db import _check_rate_limits


def _add_past_calls(
    db_conn: sqlite3.Connection, api_name: str, seconds_ago: int, count: int
) -> None:
    """Insert *count* fake query-log rows at *seconds_ago* into the past."""
    then = datetime.now(LOCAL_TIMEZONE) - timedelta(seconds=seconds_ago)
    cur = db_conn.cursor()
    for _ in range(count):
        cur.execute(
            "INSERT INTO api_queries (api_name,timestamp,status_code,error_text) VALUES (?,?,?,?)",
            (api_name, then, 200, ""),
        )
    db_conn.commit()


def test_second_rolling_limit(db_conn: sqlite3.Connection) -> None:
    api = "demo"
    rate_limits = [{"query_limit": 2, "timeframe": "second", "type": "rolling"}]

    # 2 queries in the last second → allowed after sleep handled by helper
    _add_past_calls(db_conn, api, 0, 2)
    assert _check_rate_limits(api, rate_limits, db_conn) is False  # should allow

    # 3 in window hits limit
    _add_past_calls(db_conn, api, 0, 1)
    assert _check_rate_limits(api, rate_limits, db_conn) is True  # should block
