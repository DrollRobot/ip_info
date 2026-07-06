import ipaddress
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from ip_info.config import IP_TABLE_NAME, MAX_AGE
from ip_info.db._add_to_db import _insert_ip_info
from ip_info.db._query_db import _fetch_ip_info, _is_db_entry_recent


def _make_entry(*, ip_address: str, api_name: str, timestamp: datetime) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "ip_address": ip_address,
        "api_name": api_name,
        "api_display_name": api_name.upper(),
        "risk": 0,
        "city": "",
        "state": "",
        "cc": "",
        "company": "",
        "isp": "",
        "as_name": "",
        "hostname": "",
        "flags": "",
        "raw_json": {},
    }


def test_fetch_ip_info_all_returns_all_apis_for_ip(db_conn: sqlite3.Connection) -> None:
    now = datetime.now(UTC)
    _insert_ip_info(
        entries=[
            _make_entry(ip_address="1.1.1.1", api_name="api_a", timestamp=now),
            _make_entry(ip_address="1.1.1.1", api_name="api_b", timestamp=now),
            _make_entry(ip_address="2.2.2.2", api_name="api_a", timestamp=now),
        ],
        db_conn=db_conn,
    )

    rows = _fetch_ip_info(
        api_names=["all"], ip_address=ipaddress.ip_address("1.1.1.1"), db_conn=db_conn
    )
    assert {row["api_name"] for row in rows} == {"api_a", "api_b"}
    assert all(row["ip_address"] == "1.1.1.1" for row in rows)

    other_rows = _fetch_ip_info(
        api_names=["all"], ip_address=ipaddress.ip_address("2.2.2.2"), db_conn=db_conn
    )
    assert [row["api_name"] for row in other_rows] == ["api_a"]


def test_fetch_ip_info_filters_by_api_names(db_conn: sqlite3.Connection) -> None:
    now = datetime.now(UTC)
    _insert_ip_info(
        entries=[
            _make_entry(ip_address="1.1.1.1", api_name="api_a", timestamp=now),
            _make_entry(ip_address="1.1.1.1", api_name="api_b", timestamp=now),
            _make_entry(ip_address="1.1.1.1", api_name="api_c", timestamp=now),
        ],
        db_conn=db_conn,
    )

    rows = _fetch_ip_info(
        api_names=["api_a", "api_c"],
        ip_address=ipaddress.ip_address("1.1.1.1"),
        db_conn=db_conn,
    )
    assert {row["api_name"] for row in rows} == {"api_a", "api_c"}


def test_fetch_ip_info_requires_connection() -> None:
    with pytest.raises(SystemExit):
        _fetch_ip_info(
            api_names=["all"],
            ip_address=ipaddress.ip_address("1.1.1.1"),
            db_conn=cast(sqlite3.Connection, None),
        )


def test_is_db_entry_recent_no_entries(db_conn: sqlite3.Connection) -> None:
    assert _is_db_entry_recent("api_a", ipaddress.ip_address("1.1.1.1"), db_conn) is False


def test_is_db_entry_recent_fresh_entry(db_conn: sqlite3.Connection) -> None:
    now = datetime.now(UTC)
    _insert_ip_info(
        entries=[_make_entry(ip_address="1.1.1.1", api_name="api_a", timestamp=now)],
        db_conn=db_conn,
    )

    assert _is_db_entry_recent("api_a", ipaddress.ip_address("1.1.1.1"), db_conn) is True


def test_is_db_entry_recent_old_entry(db_conn: sqlite3.Connection) -> None:
    old = datetime.now(UTC) - timedelta(days=MAX_AGE + 5)
    _insert_ip_info(
        entries=[_make_entry(ip_address="1.1.1.1", api_name="api_a", timestamp=old)],
        db_conn=db_conn,
    )

    assert _is_db_entry_recent("api_a", ipaddress.ip_address("1.1.1.1"), db_conn) is False


def test_is_db_entry_recent_naive_timestamp_treated_as_utc(
    db_conn: sqlite3.Connection,
) -> None:
    # Naive ISO strings inserted directly (bypassing the aware-only adapter) come back
    # naive from the TIMESTAMP converter; they are interpreted as UTC.
    fresh = datetime.now(UTC).replace(tzinfo=None).isoformat()
    db_conn.execute(
        # table/column identifiers are internal constants; values are parameterized
        f"INSERT INTO {IP_TABLE_NAME} (timestamp, ip_address, api_name) "  # noqa: S608
        "VALUES (?, ?, ?)",
        (fresh, "9.9.9.9", "api_naive_fresh"),
    )
    db_conn.execute(
        f"INSERT INTO {IP_TABLE_NAME} (timestamp, ip_address, api_name) "  # noqa: S608
        "VALUES (?, ?, ?)",
        ("2020-01-02T03:04:05", "9.9.9.9", "api_naive_old"),
    )
    db_conn.commit()

    assert _is_db_entry_recent("api_naive_fresh", ipaddress.ip_address("9.9.9.9"), db_conn) is True
    assert _is_db_entry_recent("api_naive_old", ipaddress.ip_address("9.9.9.9"), db_conn) is False
