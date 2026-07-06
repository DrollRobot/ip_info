import ipaddress
import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

import pytest

from ip_info._display_ip_info import display_ip_info
from ip_info.db._add_to_db import _insert_ip_info


def _make_entry(
    *,
    ip_address: str,
    api_name: str,
    api_display_name: str,
    company: str = "",
    cc: str = "US",
    raw_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC),
        "ip_address": ip_address,
        "api_name": api_name,
        "api_display_name": api_display_name,
        "risk": 0,
        "city": "Springfield",
        "state": "IL",
        "cc": cc,
        "company": company,
        "isp": "",
        "as_name": "",
        "hostname": "",
        "flags": "-",
        "raw_json": raw_json if raw_json is not None else {},
    }


def test_display_no_data(db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]) -> None:
    ip = ipaddress.ip_address("3.3.3.3")

    display_ip_info(ip_addresses=[ip], output_format="table", db_conn=db_conn)

    out = capsys.readouterr().out
    assert "No data for 3.3.3.3." in out


def test_display_rawjson(db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]) -> None:
    ip = ipaddress.ip_address("1.1.1.1")
    payload = {"key": "value", "nested": {"n": 1}}
    _insert_ip_info(
        entries=[
            _make_entry(
                ip_address="1.1.1.1",
                api_name="api_a",
                api_display_name="Alpha",
                raw_json=payload,
            )
        ],
        db_conn=db_conn,
    )

    display_ip_info(ip_addresses=[ip], output_format="rawjson", db_conn=db_conn)

    out = capsys.readouterr().out
    assert out.startswith("1.1.1.1\n")
    assert "Showing raw JSON return for 1.1.1.1 from Alpha on " in out
    # raw_json round-trips through json.dumps
    assert json.dumps(payload, indent=4) in out


def test_display_table(db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]) -> None:
    ip = ipaddress.ip_address("1.1.1.1")
    _insert_ip_info(
        entries=[
            # case-insensitive sort puts lowercase "aardvark" before "Bravo";
            # a case-sensitive sort would order "Bravo" first
            _make_entry(
                ip_address="1.1.1.1",
                api_name="api_b",
                api_display_name="Bravo",
                company="Bravo Networks",
            ),
            _make_entry(
                ip_address="1.1.1.1",
                api_name="api_a",
                api_display_name="aardvark",
                company="Example Corp",
            ),
        ],
        db_conn=db_conn,
    )

    display_ip_info(ip_addresses=[ip], output_format="table", db_conn=db_conn)

    out = capsys.readouterr().out
    assert out.startswith("1.1.1.1\n")

    # github-style table with the expected columns
    assert "| api_display_name" in out
    assert "| country" in out
    assert "| ownership" in out
    assert "|---" in out

    # country code resolved to its full name; the bare code is not shown
    assert "United States" in out

    # ownership condensed from company/isp/as_name
    assert "Example Corp" in out
    assert "Bravo Networks" in out

    # rows sorted case-insensitively by api_display_name
    assert out.index("aardvark") < out.index("Bravo")


def test_display_table_unknown_cc_falls_back_to_code(
    db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]
) -> None:
    ip = ipaddress.ip_address("1.1.1.1")
    _insert_ip_info(
        entries=[
            _make_entry(
                ip_address="1.1.1.1",
                api_name="api_a",
                api_display_name="Alpha",
                cc="ZZ",
            )
        ],
        db_conn=db_conn,
    )

    display_ip_info(ip_addresses=[ip], output_format="table", db_conn=db_conn)

    out = capsys.readouterr().out
    # "ZZ" is not a real ISO code, so the raw code is shown unchanged
    assert "ZZ" in out


def test_display_jsontable(db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]) -> None:
    ip = ipaddress.ip_address("1.1.1.1")
    _insert_ip_info(
        entries=[
            _make_entry(
                ip_address="1.1.1.1",
                api_name="api_a",
                api_display_name="Alpha",
                company="Example Corp",
            )
        ],
        db_conn=db_conn,
    )

    display_ip_info(ip_addresses=[ip], output_format="jsontable", db_conn=db_conn)

    out = capsys.readouterr().out
    result = json.loads(out)
    assert list(result) == ["1.1.1.1"]
    rendered = result["1.1.1.1"]
    assert "api_display_name" in rendered
    assert "Alpha" in rendered
    assert "Example Corp" in rendered


def test_display_none_prints_nothing(
    db_conn: sqlite3.Connection, capsys: pytest.CaptureFixture[str]
) -> None:
    ip = ipaddress.ip_address("1.1.1.1")
    _insert_ip_info(
        entries=[_make_entry(ip_address="1.1.1.1", api_name="api_a", api_display_name="Alpha")],
        db_conn=db_conn,
    )

    display_ip_info(ip_addresses=[ip], output_format="none", db_conn=db_conn)

    assert capsys.readouterr().out == ""
