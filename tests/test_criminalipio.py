"""Tests for the CriminalIP.io client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.criminalipio import criminalipio
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME

MODULE = "ip_info.apis.criminalipio"
API_NAME = "criminalipio"
API_DISPLAY_NAME = "CriminalIP.io"
API_KEY = "test-criminalip-key"  # pragma: allowlist secret


class _FakeResponse:
    """Minimal stand-in for requests.Response."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: dict[str, Any] | None = None,
        text: str = "",
        reason: str = "OK",
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data if json_data is not None else {}
        self.text = text
        self.reason = reason

    def json(self) -> dict[str, Any]:
        return self._json_data

    def raise_for_status(self) -> None:
        return None


def _rows(conn: sqlite3.Connection, table: str) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    # table name is a project constant; values are parameterized
    cursor = conn.execute(f"SELECT * FROM {table}")  # noqa: S608
    return [dict(row) for row in cursor.fetchall()]


def _patch_no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *args, **kwargs: False)


def _install_fake_get(
    monkeypatch: pytest.MonkeyPatch, responses: list[_FakeResponse]
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    queue = list(responses)

    def fake_get(url: str, **kwargs: Any) -> _FakeResponse:
        calls.append({"url": url, **kwargs})
        return queue.pop(0)

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)
    return calls


def _forbid_get(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_get(url: str, **kwargs: Any) -> _FakeResponse:
        raise AssertionError("unexpected HTTP call")

    monkeypatch.setattr(f"{MODULE}.requests.get", fail_get)


def _run(
    ip_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    db_conn: sqlite3.Connection,
) -> None:
    criminalipio(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=ip_addresses,
        rate_limits=[],
        api_key=API_KEY,
        db_conn=db_conn,
    )


def test_happy_path_all_flags(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    _patch_no_rate_limit(monkeypatch)
    result = {
        "summary": {
            "connection": {
                "hostname": "host.example.com",
                "country": "us",
                "ip_address_owner": "ExampleCo",
            },
            "detection": {
                "cdn_ip": True,
                "hosting_ip": True,
                "mobile_ip": True,
                "proxy_ip": True,
                "scanner_ip": True,
                "tor_ip": True,
                "vpn_ip": True,
            },
        },
        "ip_scoring": {"is_malicious": True},
    }
    calls = _install_fake_get(monkeypatch, [_FakeResponse(json_data=result)])

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert len(calls) == 1
    assert calls[0]["url"] == "https://api.criminalip.io/v1/asset/ip/report/summary"
    assert calls[0]["headers"] == {"x-api-key": API_KEY}
    assert calls[0]["params"] == {"ip": "1.2.3.4"}
    assert f"Querying {API_DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    ip_rows = _rows(db_conn, IP_TABLE_NAME)
    assert len(ip_rows) == 1
    row = ip_rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["company"] == "ExampleCo"
    assert row["hostname"] == "host.example.com"
    assert row["cc"] == "US"  # parsed from the response and uppercased
    assert row["flags"] == "cdn, hosting, malicious, mobile, proxy, scanner, tor, vpn"
    assert json.loads(row["raw_json"]) == result

    query_rows = _rows(db_conn, QUERY_TABLE_NAME)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_happy_path_all_defaults(
    monkeypatch: pytest.MonkeyPatch, db_conn: sqlite3.Connection
) -> None:
    _patch_no_rate_limit(monkeypatch)
    _install_fake_get(monkeypatch, [_FakeResponse(json_data={})])

    _run([ipaddress.ip_address("8.8.8.8")], db_conn)

    ip_rows = _rows(db_conn, IP_TABLE_NAME)
    assert len(ip_rows) == 1
    row = ip_rows[0]
    assert row["ip_address"] == "8.8.8.8"
    assert row["company"] == ""
    assert row["hostname"] == ""
    assert row["flags"] == "-"
    assert json.loads(row["raw_json"]) == {}


def test_ipv6_addresses_filtered_out(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    _patch_no_rate_limit(monkeypatch)
    _forbid_get(monkeypatch)

    _run([ipaddress.ip_address("2606:4700::1111")], db_conn)

    assert "Querying" not in capsys.readouterr().out
    assert _rows(db_conn, IP_TABLE_NAME) == []
    assert _rows(db_conn, QUERY_TABLE_NAME) == []


def test_rate_limit_skip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *args, **kwargs: True)
    _forbid_get(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Rate limit reached. Skipping query." in capsys.readouterr().out
    assert _rows(db_conn, IP_TABLE_NAME) == []
    assert _rows(db_conn, QUERY_TABLE_NAME) == []


def test_non_200_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    _patch_no_rate_limit(monkeypatch)
    response = _FakeResponse(status_code=429, text="quota", reason="Too Many Requests")
    _install_fake_get(monkeypatch, [response])

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    out = capsys.readouterr().out
    assert "Received status code 429, message quota. Skipping query" in out
    assert _rows(db_conn, IP_TABLE_NAME) == []
    query_rows = _rows(db_conn, QUERY_TABLE_NAME)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 429
    assert query_rows[0]["error_text"] == "Too Many Requests"


def test_request_exception(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    _patch_no_rate_limit(monkeypatch)

    def raise_get(url: str, **kwargs: Any) -> _FakeResponse:
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(f"{MODULE}.requests.get", raise_get)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    out = capsys.readouterr().out
    assert f"Error querying {API_DISPLAY_NAME} for 1.2.3.4: boom" in out
    assert _rows(db_conn, IP_TABLE_NAME) == []
    assert _rows(db_conn, QUERY_TABLE_NAME) == []


def test_recent_entry_skipped_then_next_ip_queried(
    monkeypatch: pytest.MonkeyPatch, db_conn: sqlite3.Connection
) -> None:
    _patch_no_rate_limit(monkeypatch)

    def fake_recent(
        api_name: str,
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        db_conn: sqlite3.Connection,
    ) -> bool:
        return str(ip_address) == "1.1.1.1"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    calls = _install_fake_get(monkeypatch, [_FakeResponse(json_data={})])

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("8.8.8.8")], db_conn)

    assert len(calls) == 1
    assert calls[0]["params"]["ip"] == "8.8.8.8"
    ip_rows = _rows(db_conn, IP_TABLE_NAME)
    assert len(ip_rows) == 1
    assert ip_rows[0]["ip_address"] == "8.8.8.8"
