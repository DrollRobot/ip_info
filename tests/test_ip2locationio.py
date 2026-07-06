"""Tests for the IP2Location.io client module."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ip2locationio import ip2locationio
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME

MODULE = "ip_info.apis.ip2locationio"
API_NAME = "ip2locationio"
API_DISPLAY_NAME = "IP2Location.io"
API_KEY = "test-ip2location-key"  # pragma: allowlist secret


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


def _patch_capture_rate_limits(
    monkeypatch: pytest.MonkeyPatch, *, result: bool = False
) -> list[list[dict[str, Any]]]:
    seen: list[list[dict[str, Any]]] = []

    def fake_check(
        api_name: str, rate_limits: list[dict[str, Any]], db_conn: sqlite3.Connection
    ) -> bool:
        seen.append(rate_limits)
        return result

    monkeypatch.setattr(f"{MODULE}._check_rate_limits", fake_check)
    return seen


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
    *,
    api_key: str = API_KEY,
    rate_limits: list[dict[str, Any]] | None = None,
) -> None:
    ip2locationio(
        api_name=API_NAME,
        api_display_name=API_DISPLAY_NAME,
        ip_addresses=ip_addresses,
        rate_limits=rate_limits if rate_limits is not None else [],
        api_key=api_key,
        db_conn=db_conn,
    )


def test_happy_path_proxy_flag_with_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    seen = _patch_capture_rate_limits(monkeypatch)
    result = {
        "is_proxy": True,
        "city_name": "Springfield",
        "region_name": "Illinois",
        "country_code": "US",
        "as": "AS-EXAMPLE",
    }
    calls = _install_fake_get(monkeypatch, [_FakeResponse(json_data=result)])

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    # a non-empty api_key raises the rate limits to the keyed 50k/month tier
    assert len(seen) == 1
    assert seen[0][0]["status_code"] == 10001
    assert seen[0][0]["query_limit"] == 50000
    assert seen[0][0]["timeframe"] == "month"

    assert len(calls) == 1
    assert calls[0]["url"] == "https://api.ip2location.io"
    assert calls[0]["headers"] == {}
    assert calls[0]["params"] == {"ip": "1.2.3.4", "key": API_KEY, "format": "json"}
    assert f"Querying {API_DISPLAY_NAME} for 1.2.3.4" in capsys.readouterr().out

    ip_rows = _rows(db_conn, IP_TABLE_NAME)
    assert len(ip_rows) == 1
    row = ip_rows[0]
    assert row["ip_address"] == "1.2.3.4"
    assert row["api_name"] == API_NAME
    assert row["city"] == "Springfield"
    assert row["state"] == "Illinois"
    assert row["cc"] == "US"
    assert row["as_name"] == "AS-EXAMPLE"
    assert row["flags"] == "proxy"
    assert json.loads(row["raw_json"]) == result

    query_rows = _rows(db_conn, QUERY_TABLE_NAME)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_happy_path_all_defaults_without_key(
    monkeypatch: pytest.MonkeyPatch, db_conn: sqlite3.Connection
) -> None:
    seen = _patch_capture_rate_limits(monkeypatch)
    calls = _install_fake_get(monkeypatch, [_FakeResponse(json_data={})])
    original_limits: list[dict[str, Any]] = [{"query_limit": 7, "timeframe": "day"}]

    _run(
        [ipaddress.ip_address("2606:4700::1111")],
        db_conn,
        api_key="",
        rate_limits=original_limits,
    )

    # an empty api_key keeps the caller-supplied rate limits
    assert seen == [original_limits]
    assert calls[0]["params"] == {"ip": "2606:4700::1111", "key": "", "format": "json"}

    ip_rows = _rows(db_conn, IP_TABLE_NAME)
    assert len(ip_rows) == 1
    row = ip_rows[0]
    assert row["ip_address"] == "2606:4700::1111"
    assert row["city"] == ""
    assert row["state"] == ""
    assert row["cc"] == ""
    assert row["as_name"] == ""
    assert row["flags"] == "-"
    assert json.loads(row["raw_json"]) == {}


def test_rate_limit_skip(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    _patch_capture_rate_limits(monkeypatch, result=True)
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
    _patch_capture_rate_limits(monkeypatch)
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
    _patch_capture_rate_limits(monkeypatch)

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
    _patch_capture_rate_limits(monkeypatch)

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
