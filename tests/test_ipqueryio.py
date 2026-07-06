"""Tests for the ipquery.io API client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipqueryio import ipqueryio
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipqueryio"
API_NAME = "ipqueryio"
API_DISPLAY_NAME = "IPQuery.io"
API_KEY = "unused-key"  # pragma: allowlist secret


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
    ipqueryio(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=[ipaddress.ip_address(ip) for ip in ip_strings],
        rate_limits=[],
        api_key=API_KEY,
        db_conn=db_conn,
    )


def test_single_ip_dict_response_no_flags(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A single-IP dict response is normalized to a list; all-off flags give '-'."""
    _no_rate_limit(monkeypatch)
    payload = {
        "ip": "1.2.3.4",
        "location": {"city": "Paris", "state": "Ile-de-France", "country_code": "FR"},
        "isp": {"org": "OrgCo", "isp": "IspCo", "asn": "AS123"},
        "risk": {
            "is_datacenter": False,
            "is_mobile": False,
            "is_proxy": False,
            "risk_score": 0,
            "is_tor": False,
            "is_vpn": False,
        },
    }
    calls = _patch_get(monkeypatch, [StubResponse(json_data=payload)])

    _run(db_conn, ["1.2.3.4"])

    assert calls == [{"url": "https://api.ipquery.io/1.2.3.4", "timeout": REQUEST_TIMEOUT}]
    assert f"Querying {API_DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == API_DISPLAY_NAME
    assert row["risk"] == 0
    assert row["city"] == "Paris"
    assert row["state"] == "Ile-de-France"
    assert row["cc"] == "FR"
    assert row["company"] == "OrgCo"
    assert row["isp"] == "IspCo"
    assert row["as_name"] == "AS123"
    assert row["hostname"] == ""
    assert row["flags"] == "-"
    assert json.loads(row["raw_json"]) == payload

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_multiple_ips_list_response_all_flags(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A list response covers every flag branch and missing-dict defaults."""
    _no_rate_limit(monkeypatch)
    flagged = {
        "ip": "1.2.3.4",
        "location": {"city": "Kyiv", "state": "Kyiv City", "country_code": "UA"},
        "isp": {"org": "BadOrg", "isp": "BadIsp", "asn": "AS666"},
        "risk": {
            "is_datacenter": True,
            "is_mobile": True,
            "is_proxy": True,
            "risk_score": 77,
            "is_tor": True,
            "is_vpn": True,
        },
    }
    bare = {"ip": "5.6.7.8"}
    calls = _patch_get(monkeypatch, [StubResponse(json_data=[flagged, bare])])

    _run(db_conn, ["1.2.3.4", "5.6.7.8"])

    assert calls[0]["url"] == "https://api.ipquery.io/1.2.3.4,5.6.7.8"
    assert f"Querying {API_DISPLAY_NAME} for 2 IPs" in capsys.readouterr().out

    rows = {row["ip_address"]: row for row in _ip_rows(db_conn)}
    assert len(rows) == 2

    assert rows["1.2.3.4"]["flags"] == "datacenter, mobile, proxy, risk:77, tor, vpn"
    assert rows["1.2.3.4"]["risk"] == 77

    # missing location/isp/risk dicts fall back to empty strings and zero risk
    assert rows["5.6.7.8"]["flags"] == "-"
    assert rows["5.6.7.8"]["risk"] == 0
    assert rows["5.6.7.8"]["city"] == ""
    assert rows["5.6.7.8"]["state"] == ""
    assert rows["5.6.7.8"]["cc"] == ""
    assert rows["5.6.7.8"]["company"] == ""
    assert rows["5.6.7.8"]["isp"] == ""
    assert rows["5.6.7.8"]["as_name"] == ""


def test_rate_limit_skips_chunk(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When the rate limit is reached, the chunk is skipped without a request."""
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}.requests.get", _fail)

    _run(db_conn, ["1.2.3.4"])

    assert "Rate limit reached. Skipping query." in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_all_recent_returns(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """When every IP has a recent db entry, the function returns immediately."""
    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", lambda *a, **k: True)
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", _fail)
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

    assert calls[0]["url"] == "https://api.ipquery.io/5.6.7.8"
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["5.6.7.8"]


def test_non_200_logs_query_and_skips(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Non-200 responses are logged in api_queries but produce no ip_data row."""
    _no_rate_limit(monkeypatch)
    stub = StubResponse(status_code=429, text="slow down", reason="Too Many Requests")
    _patch_get(monkeypatch, [stub])

    _run(db_conn, ["1.2.3.4"])

    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 429
    out = capsys.readouterr().out
    assert "Received status code 429, message slow down. Skipping query" in out


def test_request_exception_returns(
    db_conn: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A RequestException is reported and the function returns."""
    _no_rate_limit(monkeypatch)

    def fake_get(url: str, **kwargs: Any) -> StubResponse:
        raise requests.exceptions.Timeout("slow")

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run(db_conn, ["1.2.3.4"])

    assert f"Error querying {API_DISPLAY_NAME}: slow" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []
