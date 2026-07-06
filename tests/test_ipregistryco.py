"""Tests for the ipregistry.co API client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipregistryco import ipregistryco
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipregistryco"
API_NAME = "ipregistryco"
API_DISPLAY_NAME = "IPRegistry.co"
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
    monkeypatch.setattr(f"{MODULE}._respect_rate_limit", lambda *a, **k: False)


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
    ipregistryco(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=[ipaddress.ip_address(ip) for ip in ip_strings],
        rate_limits=[],
        api_key=API_KEY,
        db_conn=db_conn,
    )


def test_single_ip_all_security_flags(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single-result dict is wrapped in a list and every flag branch fires."""
    _no_rate_limit(monkeypatch)
    payload = {
        "ip": "1.2.3.4",
        "security": {
            "is_abuser": True,
            "is_anonymous": True,
            "is_attacker": True,
            "is_bogon": True,
            "is_cloud_provider": True,
            "is_proxy": True,
            "is_relay": True,
            "is_threat": True,
            "is_tor": True,
            "is_tor_exit": False,
            "is_vpn": True,
        },
        "location": {
            "city": "Berlin",
            "region": {"name": "Berlin"},
            "country": {"code": "DE"},
        },
        "connection": {"organization": "OrgCo", "asn": "AS3320", "domain": "example.com"},
    }
    calls = _patch_get(monkeypatch, [StubResponse(json_data=payload)])

    _run(db_conn, ["1.2.3.4"])

    assert calls == [
        {
            "url": "https://api.ipregistry.co/1.2.3.4",
            "params": {"key": API_KEY},
            "timeout": REQUEST_TIMEOUT,
        }
    ]
    assert f"Querying {API_DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == API_DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Berlin"
    assert row["state"] == "Berlin"
    assert row["cc"] == "DE"
    assert row["company"] == "OrgCo"
    assert row["isp"] == ""
    assert row["as_name"] == "AS3320"
    assert row["hostname"] == "example.com"
    assert row["flags"] == (
        "abuse, anonymous, attacker, bogon, cloud, proxy, relay, threat, tor, vpn"
    )
    assert json.loads(row["raw_json"]) == payload

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_bulk_results_list_and_edge_cases(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Bulk responses use the nested results list; tor-exit and no-ip branches covered."""
    _no_rate_limit(monkeypatch)
    payload = {
        "results": [
            # no security/location/connection dicts: defaults and "-" flags
            {"ip": "1.1.1.1"},
            # only is_tor_exit set: still yields the "tor" flag
            {"ip": "2.2.2.2", "security": {"is_tor": False, "is_tor_exit": True}},
            # no ip key: skipped entirely
            {"security": {"is_vpn": True}},
        ]
    }
    calls = _patch_get(monkeypatch, [StubResponse(json_data=payload)])

    _run(db_conn, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

    assert calls[0]["url"] == "https://api.ipregistry.co/1.1.1.1,2.2.2.2,3.3.3.3"
    assert f"Querying {API_DISPLAY_NAME} for 3 IPs" in capsys.readouterr().out

    rows = {row["ip_address"]: row for row in _ip_rows(db_conn)}
    assert set(rows) == {"1.1.1.1", "2.2.2.2"}

    assert rows["1.1.1.1"]["flags"] == "-"
    assert rows["1.1.1.1"]["city"] == ""
    assert rows["1.1.1.1"]["state"] == ""
    assert rows["1.1.1.1"]["cc"] == ""
    assert rows["1.1.1.1"]["company"] == ""
    assert rows["1.1.1.1"]["as_name"] == ""
    assert rows["1.1.1.1"]["hostname"] == ""

    assert rows["2.2.2.2"]["flags"] == "tor"


def test_rate_limit_skips_chunk(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the rate limit is reached, the chunk is skipped without a request."""
    monkeypatch.setattr(f"{MODULE}._respect_rate_limit", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)

    _run(db_conn, ["1.2.3.4"])

    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_all_recent_returns(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When every IP has a recent db entry, the function returns immediately."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}._respect_rate_limit", _fail)
    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)

    _run(db_conn, ["1.2.3.4", "5.6.7.8"])

    assert capsys.readouterr().out == ""
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_queries_only_stale(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IPs with recent db entries are filtered out of the request URL."""

    def fake_recent(api_name: str, ip: object, conn: object) -> bool:
        return str(ip) == "9.9.9.9"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    _no_rate_limit(monkeypatch)
    calls = _patch_get(monkeypatch, [StubResponse(json_data={"ip": "5.6.7.8"})])

    _run(db_conn, ["9.9.9.9", "5.6.7.8"])

    assert calls[0]["url"] == "https://api.ipregistry.co/5.6.7.8"
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["5.6.7.8"]


def test_non_200_logs_query_and_skips(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Non-200 responses are logged in api_queries but produce no ip_data row."""
    _no_rate_limit(monkeypatch)
    stub = StubResponse(status_code=403, text="forbidden", reason="Forbidden")
    _patch_get(monkeypatch, [stub])

    _run(db_conn, ["1.2.3.4"])

    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 403
    out = capsys.readouterr().out
    assert "Received status code 403, message forbidden. Skipping query" in out


def test_request_exception_returns(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A RequestException is reported and the function returns."""
    _no_rate_limit(monkeypatch)

    def fake_get(url: str, **kwargs: Any) -> StubResponse:
        raise requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run(db_conn, ["1.2.3.4"])

    assert f"Error querying {API_DISPLAY_NAME}: boom" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_list_response_raises_type_error(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-dict JSON body raises TypeError after the query is logged."""
    _no_rate_limit(monkeypatch)
    _patch_get(monkeypatch, [StubResponse(json_data=[{"ip": "1.2.3.4"}])])

    with pytest.raises(TypeError, match="Response format invalid"):
        _run(db_conn, ["1.2.3.4"])

    assert _ip_rows(db_conn) == []
    assert len(_query_rows(db_conn)) == 1
