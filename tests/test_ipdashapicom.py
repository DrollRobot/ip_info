"""Tests for the IP-API.com API client (`ip_info.apis.ipdashapicom`)."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipdashapicom import ipdashapicom
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipdashapicom"
API_NAME = "ipdashapicom"
DISPLAY_NAME = "IP-API.com"
URL = "http://ip-api.com/batch"


class _StubResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        reason: str = "OK",
    ) -> None:
        """Store the canned response attributes."""
        self.status_code = status_code
        self.text = text
        self.reason = reason
        self._json_data = json_data

    def json(self) -> Any:
        """Return the canned JSON payload."""
        return self._json_data

    def raise_for_status(self) -> None:
        """Do nothing; status handling is asserted via status_code."""


def _ip_rows(db_conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all rows from the ip_data table as dicts."""
    db_conn.row_factory = sqlite3.Row
    # table name is an internal constant; no user input involved
    cursor = db_conn.execute(f"SELECT * FROM {IP_TABLE_NAME} ORDER BY ip_address")  # noqa: S608
    return [dict(row) for row in cursor.fetchall()]


def _query_rows(db_conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return all rows from the api_queries table as dicts."""
    db_conn.row_factory = sqlite3.Row
    # table name is an internal constant; no user input involved
    cursor = db_conn.execute(f"SELECT * FROM {QUERY_TABLE_NAME}")  # noqa: S608
    return [dict(row) for row in cursor.fetchall()]


def _no_rate_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the rate-limit check in the module under test to report no limit."""
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: False)


def _forbid_http(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the module under test performs an HTTP request."""

    def _fail(url: str, **kwargs: Any) -> _StubResponse:
        raise AssertionError("HTTP request should not have been made")

    monkeypatch.setattr(f"{MODULE}.requests.post", _fail)


def _run(
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    db_conn: sqlite3.Connection,
) -> None:
    """Invoke the client with standard test arguments."""
    ipdashapicom(
        api_name=API_NAME,
        api_display_name=DISPLAY_NAME,
        ip_addresses=ip_addresses,
        rate_limits=[],
        api_key="",
        db_conn=db_conn,
    )


def test_all_recent_entries_returns_early(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """If every IP has a recent database entry, no HTTP call is made."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    _no_rate_limits(monkeypatch)
    _forbid_http(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert capsys.readouterr().out == ""
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_rate_limit_skips_chunk(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A hit rate limit prints a notice and skips the HTTP call."""
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: True)
    _forbid_http(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Rate limit reached. Skipping query." in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_single_ip_all_flags_set(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A single-IP batch parses every field and all three flags."""
    _no_rate_limits(monkeypatch)
    result = {
        "query": "1.2.3.4",
        "city": "Denver",
        "regionName": "Colorado",
        "countryCode": "US",
        "org": "ExampleOrg",
        "isp": "Example ISP",
        "asname": "EXAMPLE-AS",
        "hosting": True,
        "mobile": True,
        "proxy": True,
    }
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        calls.append({"url": url, **kwargs})
        return _StubResponse(json_data=[result])

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert calls == [
        {
            "url": URL,
            "params": {"fields": "66842623"},
            "json": ["1.2.3.4"],
            "timeout": REQUEST_TIMEOUT,
        }
    ]
    assert f"Querying {DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Denver"
    assert row["state"] == "Colorado"
    assert row["cc"] == "US"
    assert row["company"] == "ExampleOrg"
    assert row["isp"] == "Example ISP"
    assert row["as_name"] == "EXAMPLE-AS"
    assert row["hostname"] == ""
    assert row["flags"] == "hosting, mobile, proxy"
    assert json.loads(row["raw_json"]) == result

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_bulk_skips_results_without_query_ip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """Results missing a query IP are skipped; flag-less results get '-' flags."""
    _no_rate_limits(monkeypatch)
    results = [
        {"message": "invalid query"},  # no "query" key
        {"query": "2.2.2.2", "hosting": False, "mobile": False, "proxy": False},
    ]
    monkeypatch.setattr(
        f"{MODULE}.requests.post",
        lambda url, **kwargs: _StubResponse(json_data=results),
    )

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert f"Querying {DISPLAY_NAME} for 2 IPs" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "2.2.2.2"
    assert row["flags"] == "-"
    for column in ("city", "state", "cc", "company", "isp", "as_name"):
        assert row[column] == ""
    assert len(_query_rows(db_conn)) == 1


def test_chunking_splits_requests_at_100_ips(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """101 IPs are split into a 100-IP chunk and a 1-IP chunk."""
    _no_rate_limits(monkeypatch)
    ips = [ipaddress.ip_address(f"10.0.{i // 256}.{i % 256}") for i in range(101)]
    payloads: list[list[str]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        chunk = kwargs["json"]
        payloads.append(chunk)
        return _StubResponse(json_data=[{"query": ip} for ip in chunk])

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run(ips, db_conn)

    assert len(payloads) == 2
    assert len(payloads[0]) == 100
    assert payloads[1] == [str(ips[100])]

    output = capsys.readouterr().out
    assert f"Querying {DISPLAY_NAME} for 100 IPs" in output
    assert f"Querying {DISPLAY_NAME} for {ips[100]}" in output

    assert len(_ip_rows(db_conn)) == 101
    assert len(_query_rows(db_conn)) == 2


def test_non_200_response_skips_insert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A non-200 status logs the query but does not insert IP data."""
    _no_rate_limits(monkeypatch)
    stub = _StubResponse(status_code=429, text="too many", reason="Too Many Requests")
    monkeypatch.setattr(f"{MODULE}.requests.post", lambda url, **kwargs: stub)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Received status code 429, message too many. Skipping query" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 429


def test_request_exception_returns_early(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A network error prints an error message, writes nothing, and returns."""
    _no_rate_limits(monkeypatch)

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert f"Error querying {DISPLAY_NAME}: boom" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_entries_only_queries_stale_ips(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """IPs with recent entries are filtered out of the batch payload."""
    _no_rate_limits(monkeypatch)

    def fake_recent(
        api_name: str,
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        db_conn: sqlite3.Connection,
    ) -> bool:
        return str(ip_address) == "1.1.1.1"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    payloads: list[list[str]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        payloads.append(kwargs["json"])
        return _StubResponse(json_data=[{"query": "2.2.2.2"}])

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert payloads == [["2.2.2.2"]]
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["2.2.2.2"]
