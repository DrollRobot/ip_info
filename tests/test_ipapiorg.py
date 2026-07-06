"""Tests for the ip-api.org API client (`ip_info.apis.ipapiorg`)."""

import ipaddress
import json
import sqlite3
from typing import Any

import pytest
import requests

from ip_info.apis.ipapiorg import ipapiorg
from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, REQUEST_TIMEOUT

MODULE = "ip_info.apis.ipapiorg"
API_NAME = "ipapiorg"
DISPLAY_NAME = "IPAPI.org"
API_KEY = "secret-key"  # pragma: allowlist secret
URL = "https://pro.ipapi.org/api_json/batch.php"


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
    ipapiorg(
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
    monkeypatch.setattr(f"{MODULE}._check_rate_limits", lambda *a, **k: True)
    _forbid_http(monkeypatch)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Rate limit reached. Skipping query." in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_single_ip_dict_response_all_flags(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """A dict response for a single IP is normalized to a list and fully parsed."""
    _no_rate_limits(monkeypatch)
    result = {
        "status": "success",
        "query": "1.2.3.4",
        "city": "Munich",
        "regionName": "Bavaria",
        "region": "BY",
        "countryCode": "DE",
        "isp": "Example ISP",
        "as": "AS3320 Example",
        "hosting": True,
        "mobile": True,
        "proxy": True,
    }
    calls: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        calls.append({"url": url, **kwargs})
        return _StubResponse(json_data=result)

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert calls == [
        {
            "url": URL,
            "params": {"key": API_KEY, "ips": "1.2.3.4"},
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
    assert row["city"] == "Munich"
    assert row["state"] == "Bavaria"
    assert row["cc"] == "DE"
    assert row["company"] == ""
    assert row["isp"] == "Example ISP"
    assert row["as_name"] == "AS3320 Example"
    assert row["hostname"] == ""
    assert row["flags"] == "hosting, mobile, proxy"
    assert json.loads(row["raw_json"]) == result

    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["api_name"] == API_NAME
    assert query_rows[0]["status_code"] == 200


def test_bulk_list_response_with_failed_and_empty_results(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """Failed results and results without a query IP are skipped; the rest parse."""
    _no_rate_limits(monkeypatch)
    results = [
        {"status": "fail", "message": "invalid query"},
        {"status": "success"},  # no "query" key
        {
            "status": "success",
            "query": "3.3.3.3",
            "city": "Montreal",
            "regionName": "",
            "region": "QC",
            "countryCode": "CA",
        },
    ]
    monkeypatch.setattr(
        f"{MODULE}.requests.get",
        lambda url, **kwargs: _StubResponse(json_data=results),
    )

    _run(
        [
            ipaddress.ip_address("1.1.1.1"),
            ipaddress.ip_address("2.2.2.2"),
            ipaddress.ip_address("3.3.3.3"),
        ],
        db_conn,
    )

    output = capsys.readouterr().out
    assert f"Querying {DISPLAY_NAME} for 3 IPs" in output
    assert "Query failed: invalid query" in output

    rows = _ip_rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert row["ip_address"] == "3.3.3.3"
    assert row["state"] == "QC"  # falls back to "region" when "regionName" is empty
    assert row["flags"] == "-"  # no flag fields set
    assert row["isp"] == ""
    assert row["as_name"] == ""
    assert len(_query_rows(db_conn)) == 1


def test_chunking_splits_requests_at_100_ips(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    db_conn: sqlite3.Connection,
) -> None:
    """101 IPs are split into a 100-IP chunk and a 1-IP chunk."""
    _no_rate_limits(monkeypatch)
    ips = [ipaddress.ip_address(f"10.0.{i // 256}.{i % 256}") for i in range(101)]
    ip_params: list[list[str]] = []

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        chunk = kwargs["params"]["ips"].split(",")
        ip_params.append(chunk)
        results = [{"status": "success", "query": ip} for ip in chunk]
        return _StubResponse(json_data=results)

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run(ips, db_conn)

    assert len(ip_params) == 2
    assert len(ip_params[0]) == 100
    assert ip_params[1] == [str(ips[100])]

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
    stub = _StubResponse(status_code=403, text="denied", reason="Forbidden")
    monkeypatch.setattr(f"{MODULE}.requests.get", lambda url, **kwargs: stub)

    _run([ipaddress.ip_address("1.2.3.4")], db_conn)

    assert "Received status code 403, message denied. Skipping query" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    query_rows = _query_rows(db_conn)
    assert len(query_rows) == 1
    assert query_rows[0]["status_code"] == 403


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

    assert f"Error querying {DISPLAY_NAME}: boom" in capsys.readouterr().out
    assert _ip_rows(db_conn) == []
    assert _query_rows(db_conn) == []


def test_mixed_recent_entries_only_queries_stale_ips(
    monkeypatch: pytest.MonkeyPatch,
    db_conn: sqlite3.Connection,
) -> None:
    """IPs with recent entries are filtered out of the bulk request."""
    _no_rate_limits(monkeypatch)

    def fake_recent(
        api_name: str,
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        db_conn: sqlite3.Connection,
    ) -> bool:
        return str(ip_address) == "1.1.1.1"

    monkeypatch.setattr(f"{MODULE}._is_db_entry_recent", fake_recent)
    params_seen: list[dict[str, Any]] = []

    def fake_get(url: str, **kwargs: Any) -> _StubResponse:
        params_seen.append(kwargs["params"])
        return _StubResponse(json_data=[{"status": "success", "query": "2.2.2.2"}])

    monkeypatch.setattr(f"{MODULE}.requests.get", fake_get)

    _run([ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")], db_conn)

    assert params_seen == [{"key": API_KEY, "ips": "2.2.2.2"}]
    rows = _ip_rows(db_conn)
    assert [row["ip_address"] for row in rows] == ["2.2.2.2"]
