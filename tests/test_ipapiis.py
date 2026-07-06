"""Tests for the ipapi.is API client (`ip_info.apis.ipapiis`)."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipapiis import ipapiis
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipapiis"
API_NAME = "ipapiis"
DISPLAY_NAME = "IPAPI.is"
API_KEY = "secret-key"  # pragma: allowlist secret
URL = "https://api.ipapi.is"


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
    monkeypatch.setattr(f"{MODULE}._respect_rate_limit", lambda *a, **k: False)


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
    ipapiis(
        api_name=API_NAME,
        api_display_name=DISPLAY_NAME,
        ip_addresses=ip_addresses,
        rate_limits=[],
        api_key=API_KEY,
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
    monkeypatch.setattr(f"{MODULE}._respect_rate_limit", lambda *a, **k: True)
    _forbid_http(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_single_ip_all_flags_set(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A single-IP query parses every flag, the VPN service, and location fields."""
    _no_rate_limits(monkeypatch)
    result = {
        "is_abuser": True,
        "is_bogon": True,
        "is_datacenter": True,
        "is_mobile": True,
        "is_proxy": True,
        "is_satellite": True,
        "is_tor": True,
        "is_vpn": True,
        "vpn": {"service": "NordVPN"},
        "asn": {"abuser_score": "0.9 (High)", "org": "Example AS"},
        "company": {"abuser_score": "0.7 (Elevated)", "name": "ExampleCo"},
        "location": {"city": "Oslo", "state": "Oslo", "country_code": "NO"},
    }
    calls: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        calls.append({"url": url, **kwargs})
        return _StubResponse(json_data={"1.2.3.4": result, "total_elapsed_ms": 12})

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert calls == [
        {
            "url": URL,
            "headers": {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
            },
            "json": {"ips": ["1.2.3.4"], "key": API_KEY},
            "timeout": REQUEST_TIMEOUT,
        }
    ]
    assert f"Querying {DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 1  # the total_elapsed_ms key is skipped
    row = rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["api_display_name"] == DISPLAY_NAME
    assert row["risk"] == ""
    assert row["city"] == "Oslo"
    assert row["state"] == "Oslo"
    assert row["cc"] == "NO"
    assert row["company"] == "ExampleCo"
    assert row["isp"] == ""
    assert row["as_name"] == "Example AS"
    assert row["hostname"] == ""
    assert row["flags"] == (
        "abuse, as_risk:High, bogon, company_risk:Elevated, datacenter, "
        "mobile, proxy, satellite, tor, vpn, NordVPN"
    )
    assert json.loads(row["raw_json"]) == result

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_bulk_low_scores_and_empty_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """Low abuser scores are suppressed and missing nested dicts default to empty."""
    _no_rate_limits(monkeypatch)
    low_score_result = {
        "is_abuser": False,
        "is_vpn": False,
        "asn": {"abuser_score": "0.001 (Low)"},
        "company": {"abuser_score": "0 (Very Low)"},
    }
    results = {"1.1.1.1": low_score_result, "2.2.2.2": {}}
    monkeypatch.setattr(
        f"{MODULE}.requests.post",
        lambda url, **kwargs: _StubResponse(json_data=results),
    )

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert f"Querying {DISPLAY_NAME} for 2 IPs" in capsys.readouterr().out

    rows = _ip_rows(db_conn)
    assert len(rows) == 2
    assert rows[0]["ip_address"] == "1.1.1.1"
    assert rows[0]["flags"] == "-"
    assert rows[1]["ip_address"] == "2.2.2.2"
    assert rows[1]["flags"] == "-"
    for column in ("city", "state", "cc", "company", "as_name"):
        assert rows[1][column] == ""
    assert len(_query_rows(db_conn)) == 1


def test_vpn_without_service_name(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """A VPN flag with no service name appends only the vpn flag."""
    _no_rate_limits(monkeypatch)
    results = {"1.2.3.4": {"is_vpn": True, "vpn": {"service": ""}}}
    monkeypatch.setattr(
        f"{MODULE}.requests.post",
        lambda url, **kwargs: _StubResponse(json_data=results),
    )

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert _ip_rows(db_conn)[0]["flags"] == "vpn"


def test_chunking_splits_requests_at_100_ips(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """101 IPs are split into a 100-IP chunk and a 1-IP chunk."""
    _no_rate_limits(monkeypatch)
    ips = [ipaddress.ip_address(f"10.0.{i // 256}.{i % 256}") for i in range(101)]
    payloads: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        payload = kwargs["json"]
        payloads.append(payload)
        return _StubResponse(json_data={ip: {} for ip in payload["ips"]})

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run(ips, db_conn)

    assert len(payloads) == 2
    assert len(payloads[0]["ips"]) == 100
    assert len(payloads[1]["ips"]) == 1
    assert payloads[1]["ips"] == [str(ips[100])]

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


def test_request_exception_skips_insert(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A network error prints an error message and writes nothing."""
    _no_rate_limits(monkeypatch)

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert f"Error querying {DISPLAY_NAME} for IPs ['1.2.3.4']: boom" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_entries_only_queries_stale_ips(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """IPs with recent entries are filtered out of the bulk payload."""
    _no_rate_limits(monkeypatch)

    def fake_recent(
        api_name: str,
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        db_conn: sqlite3.Connection,
    ) -> bool:
        return str(ip_address) == "1.1.1.1"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    payloads: list[dict[str, Any]] = []

    def fake_post(url: str, **kwargs: Any) -> _StubResponse:
        payloads.append(kwargs["json"])
        return _StubResponse(json_data={"2.2.2.2": {}})

    monkeypatch.setattr(f"{MODULE}.requests.post", fake_post)

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert payloads == [{"ips": ["2.2.2.2"], "key": API_KEY}]
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["2.2.2.2"]
