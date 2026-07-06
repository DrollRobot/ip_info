import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from ip_info.config import IP_INSERT_ORDER, IP_TABLE_NAME
from ip_info.db._add_to_db import _insert_ip_info


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
