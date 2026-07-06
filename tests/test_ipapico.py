"""Tests for the ipapi.co API client (`ip_info.apis.ipapico`)."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipapico import ipapico
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipapico"
API_NAME = "ipapico"
DISPLAY_NAME = "IPAPI.co"


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

    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)


def _run(
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    db_conn: sqlite3.Connection,
) -> None:
    """Invoke the client with standard test arguments."""
    ipapico(
        api_name=API_NAME,
        api_display_name=DISPLAY_NAME,
        ip_addresses=ip_addresses,
        rate_limits=[],
        api_key="",
        db_conn=db_conn,
    )


def test_recent_entry_skips_query(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A recent database entry short-circuits before any HTTP call."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    _no_rate_limits(monkeypatch)
    _forbid_http(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert capsys.readouterr().out == ""
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_rate_limit_skips_query(
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


def test_successful_query_inserts_entry(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A 200 response is parsed and written to ip_data and api_queries."""
    _no_rate_limits(monkeypatch)
    result = {
        "city": "Boston",
        "region": "Massachusetts",
        "country": "US",
        "org": "ExampleOrg",
        "asn": "AS13335",
    }
    calls: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        calls.append({"url": url, **kwargs})
        return _StubResponse(json_data=result)

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert calls == [{"url": "https://ipapi.co/1.2.3.4/json/", "timeout": REQUEST_TIMEOUT}]
    assert f"Querying {DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Boston"
    assert row["state"] == "Massachusetts"
    assert row["cc"] == "US"
    assert row["company"] == "ExampleOrg"
    assert row["isp"] == ""
    assert row["as_name"] == "AS13335"
    assert row["hostname"] == ""
    assert row["flags"] == ""
    assert json.loads(row["raw_json"]) == result

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_missing_fields_default_to_empty(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """Absent keys in the response body fall back to empty strings."""
    _no_rate_limits(monkeypatch)
    monkeypatch.setattr(
        f"{MODULE}.requests.get",
        lambda url, **kwargs: _StubResponse(json_data={}),
    )

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    row = _ip_rows(db_conn)[0]
    for column in ("city", "state", "cc", "company", "as_name"):
        assert row[column] == ""
    assert json.loads(row["raw_json"]) == {}


def test_non_200_response_skips_insert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A non-200 status logs the query but does not insert IP data."""
    _no_rate_limits(monkeypatch)
    stub = _StubResponse(status_code=429, text="too many", reason="Too Many Requests")
    monkeypatch.setattr(f"{MODULE}.requests.get", lambda url, **kwargs: stub)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Received status code 429, message too many. Skipping query" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 429
    assert query_rows[0]["error_text"] == "Too Many Requests"


def test_request_exception_skips_insert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A network error prints an error message and writes nothing."""
    _no_rate_limits(monkeypatch)

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert f"Error querying {DISPLAY_NAME} for 1.2.3.4: boom" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_entries_only_queries_stale_ips(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """Only IPs without a recent entry are queried."""
    _no_rate_limits(monkeypatch)

    def fake_recent(
        api_name: str,
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        db_conn: sqlite3.Connection,
    ) -> bool:
        return str(ip_address) == "1.1.1.1"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    urls: list[str] = []

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        urls.append(url)
        return _StubResponse(json_data={})

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert urls == ["https://ipapi.co/2.2.2.2/json/"]
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["2.2.2.2"]
