import json
import sqlite3
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import requests

from ip_info.config import IP_INSERT_ORDER, IP_TABLE_NAME, QUERY_TABLE_NAME
from ip_info.db._add_to_db import _insert_ip_info, _insert_query_info


class _StubResponse:
    """Minimal stand-in for requests.Response with the attributes used."""

    def __init__(self, status_code: int, reason: str) -> None:
        self.status_code = status_code
        self.reason = reason


def _single_row(conn: sqlite3.Connection) -> dict[str, Any]:
    conn.row_factory = sqlite3.Row
    # table/column identifiers are internal constants; values are parameterized
    cur = conn.execute(f"SELECT * FROM {IP_TABLE_NAME}")  # noqa: S608
    return dict(cur.fetchone())


def test_upsert_overwrites(db_conn: sqlite3.Connection) -> None:
    ts1 = datetime.now(UTC)
    first = {
        "timestamp": ts1,
        "ip_address": "1.1.1.1",
        "api_name": "abc",
        "api_display_name": "ABC",
        "risk": 0,
        "city": "X",
        "state": "Y",
        "cc": "US",
        "company": "",
        "isp": "",
        "as_name": "",
        "hostname": "",
        "flags": "-",
        "raw_json": {},
    }
    _insert_ip_info(entries=[first], db_conn=db_conn)

    # second write with same (api_name, ip) should overwrite
    ts2 = datetime.now(UTC)
    second = first | {"timestamp": ts2, "risk": 99}
    _insert_ip_info(entries=[second], db_conn=db_conn)

    row = _single_row(db_conn)
    assert row["risk"] == 99  # updated field
    assert row["timestamp"] == ts2  # updated field
    assert json.loads(row["raw_json"]) == {}  # serialised OK

    # check all expected columns present
    assert set(row) >= set(IP_INSERT_ORDER)


def test_insert_ip_info_requires_connection() -> None:
    with pytest.raises(SystemExit):
        _insert_ip_info(entries=[], db_conn=cast(sqlite3.Connection, None))


def test_insert_ip_info_rejects_single_mapping(db_conn: sqlite3.Connection) -> None:
    single = cast(list[dict[str, Any]], {"ip_address": "1.1.1.1"})
    with pytest.raises(SystemExit):
        _insert_ip_info(entries=single, db_conn=db_conn)


def test_insert_ip_info_rejects_non_iterable(db_conn: sqlite3.Connection) -> None:
    with pytest.raises(SystemExit):
        _insert_ip_info(entries=cast(list[dict[str, Any]], 42), db_conn=db_conn)


def test_insert_ip_info_rejects_non_mapping_item(db_conn: sqlite3.Connection) -> None:
    entries = cast(list[dict[str, Any]], ["not-a-dict"])
    with pytest.raises(SystemExit):
        _insert_ip_info(entries=entries, db_conn=db_conn)


def test_insert_query_info_round_trip(db_conn: sqlite3.Connection) -> None:
    stub = _StubResponse(status_code=429, reason="Too Many Requests")
    _insert_query_info("abc", cast(requests.Response, stub), db_conn)

    db_conn.row_factory = sqlite3.Row
    # table/column identifiers are internal constants; values are parameterized
    row = db_conn.execute(f"SELECT * FROM {QUERY_TABLE_NAME}").fetchone()  # noqa: S608

    assert row["api_name"] == "abc"
    assert row["status_code"] == 429
    assert row["error_text"] == "Too Many Requests"
    # the TIMESTAMP converter returns a timezone-aware datetime
    assert isinstance(row["timestamp"], datetime)
    assert row["timestamp"].tzinfo is not None


def test_insert_query_info_requires_connection() -> None:
    stub = _StubResponse(status_code=200, reason="OK")
    with pytest.raises(SystemExit):
        _insert_query_info("abc", cast(requests.Response, stub), cast(sqlite3.Connection, None))
