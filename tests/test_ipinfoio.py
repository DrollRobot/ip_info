"""Tests for the IPinfo (ipinfo.io) API client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest

from ip_info.apis.ipinfoio import ipinfoio
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME

MODULE = "ip_info.apis.ipinfoio"
API_NAME = "ipinfoio"
API_DISPLAY_NAME = "IPInfo.io"
API_KEY = "fake-api-key"  # pragma: allowlist secret


class StubHandler:
    """Minimal stand-in for the handler returned by ipinfo.getHandler."""

    def __init__(
        self,
        *,
        results: dict[str, dict[str, Any]] | None = None,
        error: Exception | None = None,
    ) -> None:
        """Store canned batch results or an error to raise."""
        self.results = results if results is not None else {}
        self.error = error
        self.batch_calls: list[list[str]] = []

    def getBatchDetails(self, ip_strings: list[str]) -> dict[str, dict[str, Any]]:
        """Record the requested IPs and return the canned results (or raise)."""
        self.batch_calls.append(ip_strings)
        if self.error is not None:
            raise self.error
        return self.results


def _fail(*args: object, **kwargs: object) -> Any:
    """Fail the test if this stand-in is ever called."""
    raise AssertionError("unexpected call")


def _patch_handler(monkeypatch: pytest.MonkeyPatch, handler: StubHandler) -> list[dict[str, Any]]:
    """Replace ipinfo.getHandler in the module under test; record handler creation."""
    created: list[dict[str, Any]] = []

    def fake_get_handler(api_key: str, **kwargs: Any) -> StubHandler:
        created.append({"api_key": api_key, **kwargs})
        return handler

    monkeypatch.setattr(f"{MODULE}.ipinfo.getHandler", fake_get_handler)
    return created


def _ip_rows(db_conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all rows from the ip_data table as dicts."""
    db_conn.row_factory = sqlite3.Row
    # table name is an internal constant
    cursor = db_conn.execute(f"SELECT * FROM {IP_TABLE_NAME}")  # noqa: S608
    return [dict(row) for row in cursor.fetchall()]


def _query_rows(db_conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all rows from the api_queries table as dicts."""
    db_conn.row_factory = sqlite3.Row
    # table name is an internal constant
    cursor = db_conn.execute(f"SELECT * FROM {QUERY_TABLE_NAME}")  # noqa: S608
    return [dict(row) for row in cursor.fetchall()]


def _run(db_conn: sqlite3.Connection, ip_strings: list[str]) -> None:
    """Invoke the client under test for the given IP address strings."""
    ipinfoio(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=[ipaddress.ip_address(ip) for ip in ip_strings],
        rate_limits=[],
        api_key=API_KEY,
        db_conn=db_conn,
    )


def test_single_ip_success_parses_org(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single IP result is parsed, org split into AS number and company."""
    details = {
        "org": "AS13335 Cloudflare, Inc.",
        "city": "Brisbane",
        "region": "Queensland",
        "country": "AU",
        "hostname": "one.one.one.one",
    }
    handler = StubHandler(results={"1.1.1.1": details})
    created = _patch_handler(monkeypatch, handler)

    _run(db_conn, ["1.1.1.1"])

    assert created == [{"api_key": API_KEY, "request_options": {"timeout": 5}}]
    assert handler.batch_calls == [["1.1.1.1"]]
    assert f"Querying {API_DISPLAY_NAME} for 1.1.1.1" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.1.1.1"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == API_DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Brisbane"
    assert row["state"] == "Queensland"
    assert row["cc"] == "AU"
    assert row["company"] == "Cloudflare, Inc."
    assert row["isp"] == ""
    assert row["as_name"] == "AS13335"
    assert row["hostname"] == "one.one.one.one"
    assert row["flags"] == ""
    assert json.loads(row["raw_json"]) == details

    # this client never logs into the query table
    assert _query_rows(db_conn) == []


def test_multiple_ips_org_variants(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Multiple IPs use the bulk print branch and cover all org parsing shapes."""
    results = {
        # no org key at all: empty as_name and company
        "1.1.1.1": {"city": "A"},
        # org without an AS prefix: company only takes the tail
        "2.2.2.2": {"org": "Google LLC"},
        # bare AS number: as_name only
        "3.3.3.3": {"org": "AS15169"},
    }
    handler = StubHandler(results=results)
    _patch_handler(monkeypatch, handler)

    _run(db_conn, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

    assert f"Querying {API_DISPLAY_NAME} for 3 IPs" in capsys.readouterr().out
    assert handler.batch_calls == [["1.1.1.1", "2.2.2.2", "3.3.3.3"]]

    rows = {row["ip_address"]: row for row in _ip_rows(db_conn)}
    assert len(rows) == 3
    assert rows["1.1.1.1"]["as_name"] == ""
    assert rows["1.1.1.1"]["company"] == ""
    assert rows["1.1.1.1"]["hostname"] == ""
    assert rows["2.2.2.2"]["as_name"] == ""
    assert rows["2.2.2.2"]["company"] == "LLC"
    assert rows["3.3.3.3"]["as_name"] == "AS15169"
    assert rows["3.3.3.3"]["company"] == ""


def test_all_recent_returns_without_query(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When every IP has a recent db entry, the function returns immediately."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}.ipinfo.getHandler", _fail)

    _run(db_conn, ["1.1.1.1", "2.2.2.2"])

    assert capsys.readouterr().out == ""
    assert _ip_rows(db_conn) == []


def test_mixed_recent_filters_ips(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IPs with recent db entries are filtered out of the batch request."""

    def fake_recent(api_name: str, ip: object, conn: object) -> bool:
        return str(ip) == "9.9.9.9"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    handler = StubHandler(results={"5.6.7.8": {}})
    _patch_handler(monkeypatch, handler)

    _run(db_conn, ["9.9.9.9", "5.6.7.8"])

    assert handler.batch_calls == [["5.6.7.8"]]
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["5.6.7.8"]


def test_batch_error_prints_and_returns(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Any exception from the batch call is reported and nothing is stored."""
    handler = StubHandler(error=RuntimeError("quota exceeded"))
    _patch_handler(monkeypatch, handler)

    _run(db_conn, ["1.1.1.1"])

    assert f"Error querying {API_DISPLAY_NAME}: quota exceeded" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
