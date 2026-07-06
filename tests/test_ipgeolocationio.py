"""Tests for the ipgeolocation.io API client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipgeolocationio import ipgeolocationio
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipgeolocationio"
API_NAME = "ipgeolocationio"
API_DISPLAY_NAME = "IPGeolocation.io"
API_KEY = "fake-api-key"  # pragma: allowlist secret


class StubResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        reason: str = "OK",
    ) -> None:
        """Store the canned response values."""
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self.reason = reason

    def json(self) -> Any:
        """Return the canned JSON payload."""
        return self._json_data

    def raise_for_status(self) -> None:
        """No-op; only reached for 200 responses in these tests."""
        return None


def _fail(*args: object, **kwargs: object) -> Any:
    """Fail the test if this stand-in is ever called."""
    raise AssertionError("unexpected call")


def _no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the module-level rate limit check to report no limit reached."""
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: False)


def _patch_get(
    monkeypatch: pytest.MonkeyPatch, responses: list[StubResponse]
) -> list[dict[str, Any]]:
    """Replace requests.get in the module under test; record calls, replay responses."""
    calls: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs: Any) -> StubResponse:
        calls.append({"url": url, **kwargs})
        return responses[len(calls) - 1]

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)
    return calls


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
    ipgeolocationio(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=[ipaddress.ip_address(ip) for ip in ip_strings],
        rate_limits=[],
        api_key=API_KEY,
        db_conn=db_conn,
    )


def test_success_inserts_parsed_row(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A 200 response is parsed into an ip_data row and logged in api_queries."""
    _no_rate_limit(monkeypatch)
    payload = {"location": {"city": "Sydney", "state_prov": "NSW", "country_code2": "AU"}}
    calls = _patch_get(monkeypatch, [StubResponse(json_data=payload)])

    _run(db_conn, ["1.2.3.4"])

    assert calls == [
        {
            "url": "https://api.ipgeolocation.io/v2/ipgeo",
            "params": {"apiKey": API_KEY, "ip": "1.2.3.4"},
            "timeout": REQUEST_TIMEOUT,
        }
    ]

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == API_DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Sydney"
    assert row["state"] == "NSW"
    assert row["cc"] == "AU"
    assert row["company"] == ""
    assert row["isp"] == ""
    assert row["as_name"] == ""
    assert row["hostname"] == ""
    assert row["flags"] == ""
    assert json.loads(row["raw_json"]) == payload

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200
    assert query_rows[0]["error_text"] == "OK"

    assert f"Querying {API_DISPLAY_NAME} for IP 1.2.3.4" in capsys.readouterr().out


def test_missing_location_uses_defaults(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A payload without a location dict falls back to empty-string fields."""
    _no_rate_limit(monkeypatch)
    _patch_get(monkeypatch, [StubResponse(json_data={})])

    _run(db_conn, ["1.2.3.4"])

    row = _ip_rows(db_conn)[0]
    assert row["city"] == ""
    assert row["state"] == ""
    assert row["cc"] == ""
    assert json.loads(row["raw_json"]) == {}


def test_recent_entry_skips_all(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IPs with a recent db entry are skipped before any rate check or request."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", _fail)
    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)

    _run(db_conn, ["1.2.3.4", "5.6.7.8"])

    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_entries_queries_only_stale(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only IPs without a recent db entry are queried."""

    def fake_recent(api_name: str, ip: object, conn: object) -> bool:
        return str(ip) == "9.9.9.9"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    _no_rate_limit(monkeypatch)
    calls = _patch_get(monkeypatch, [StubResponse(json_data={})])

    _run(db_conn, ["9.9.9.9", "5.6.7.8"])

    assert len(calls) == 1
    assert calls[0]["params"]["ip"] == "5.6.7.8"
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["5.6.7.8"]


def test_rate_limit_skips_query(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the rate limit is reached, no HTTP request is made."""
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)

    _run(db_conn, ["1.2.3.4"])

    assert "Rate limit reached. Skipping query." in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_non_200_logs_query_and_skips(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Non-200 responses are logged in api_queries but produce no ip_data row."""
    _no_rate_limit(monkeypatch)
    stub = StubResponse(status_code=429, text="quota exceeded", reason="Too Many Requests")
    _patch_get(monkeypatch, [stub])

    _run(db_conn, ["1.2.3.4"])

    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 429
    assert query_rows[0]["error_text"] == "Too Many Requests"
    out = capsys.readouterr().out
    assert "Received status code 429, message quota exceeded. Skipping query" in out


def test_request_exception_continues_to_next_ip(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A RequestException is reported and the loop continues with the next IP."""
    _no_rate_limit(monkeypatch)
    success = StubResponse(json_data={})

    def fake_get(url: str, **kwargs: Any) -> StubResponse:
        if kwargs["params"]["ip"] == "1.2.3.4":
            raise requests.exceptions.ConnectionError("boom")
        return success

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run(db_conn, ["1.2.3.4", "5.6.7.8"])

    out = capsys.readouterr().out
    assert f"Error querying {API_DISPLAY_NAME} for 1.2.3.4: boom" in out
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["5.6.7.8"]
    # only the successful call reached _insert_query_info
    assert len(_query_rows(db_conn)) == 1
