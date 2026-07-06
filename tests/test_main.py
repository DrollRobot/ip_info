"""Tests for ip_info.main: threaded provider dispatch, main(), and the argparse CLI."""

import ipaddress
import sqlite3
import sys
from pathlib import Path
from typing import Any

import pytest

from ip_info import main as main_module
from ip_info.config import API_METADATA

GOOGLE_DNS = ipaddress.ip_address("8.8.8.8")


@pytest.fixture
def tmp_db_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    monkeypatch.setattr(main_module, "DB_PATH", path)
    return path


@pytest.fixture
def display_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_display_ip_info(**kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(main_module, "display_ip_info", fake_display_ip_info)
    return calls


def _install_provider_stub(
    monkeypatch: pytest.MonkeyPatch, api_name: str, api_key: str | None
) -> list[dict[str, Any]]:
    """Stub one provider function and _get_api_key in the main module namespace."""
    calls: list[dict[str, Any]] = []

    def fake_provider(**kwargs: Any) -> None:
        calls.append(kwargs)

    def fake_get_api_key(name: str) -> str | None:
        return api_key

    monkeypatch.setattr(main_module, api_name, fake_provider)
    monkeypatch.setattr(main_module, "_get_api_key", fake_get_api_key)
    return calls


# --- run_api_function_threadsafe ---


def test_run_api_function_threadsafe_happy_path(tmp_db_path: str) -> None:
    recorded: dict[str, Any] = {}

    def fake_api(**kwargs: Any) -> None:
        recorded.update(kwargs)

    ip_addresses = [GOOGLE_DNS]
    rate_limits: list[dict[str, Any]] = [{"query_limit": 1, "timeframe": "day"}]

    main_module.run_api_function_threadsafe(
        fake_api, "fakeapi", "Fake API", ip_addresses, rate_limits, "secret"
    )

    assert recorded["api_name"] == "fakeapi"
    assert recorded["api_display_name"] == "Fake API"
    assert recorded["ip_addresses"] == ip_addresses
    assert recorded["rate_limits"] == rate_limits
    assert recorded["api_key"] == "secret"  # pragma: allowlist secret
    assert isinstance(recorded["db_conn"], sqlite3.Connection)
    # the connection is closed in the finally block
    with pytest.raises(sqlite3.ProgrammingError):
        recorded["db_conn"].execute("SELECT 1")


def test_run_api_function_threadsafe_exception_is_caught(
    tmp_db_path: str, capsys: pytest.CaptureFixture[str]
) -> None:
    def broken_api(**kwargs: Any) -> None:
        raise ValueError("boom")

    main_module.run_api_function_threadsafe(broken_api, "badapi", "Bad API", [], [], None)

    captured = capsys.readouterr()
    assert "[ERROR] Exception in thread for badapi" in captured.out
    assert "ValueError: boom" in captured.err


# --- main() ---


def test_main_user_input_no_apis_displays_validated_ips(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_module.main(user_input=["8.8.8.8", "not-an-ip"], query_apis=[], output_format="table")

    assert "Removed invalid IP: not-an-ip" in capsys.readouterr().out
    assert len(display_calls) == 1
    call = display_calls[0]
    assert call["ip_addresses"] == [GOOGLE_DNS]
    assert call["output_format"] == "table"
    assert isinstance(call["db_conn"], sqlite3.Connection)


def test_main_unknown_api_is_skipped(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_module.main(user_input=["8.8.8.8"], query_apis=["nosuchapi"], output_format="none")

    assert "Unknown API 'nosuchapi' - skipping" in capsys.readouterr().out
    assert len(display_calls) == 1


def test_main_missing_key_skips_api_silently(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert API_METADATA["abstractapicom"]["requires_key"] is True
    provider_calls = _install_provider_stub(monkeypatch, "abstractapicom", api_key=None)

    main_module.main(user_input=["8.8.8.8"], query_apis=["abstractapicom"], output_format="none")

    assert provider_calls == []
    out = capsys.readouterr().out
    assert "Unknown API" not in out
    assert "No implementation found" not in out
    assert "[ERROR]" not in out
    assert len(display_calls) == 1


def test_main_metadata_without_implementation(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_metadata: dict[str, dict[str, Any]] = dict(API_METADATA)
    fake_metadata["fakeprovider"] = {
        "api_display_name": "Fake Provider",
        "requires_key": False,
        "allows_bulk": False,
        "rate_limits": [],
    }
    monkeypatch.setattr(main_module, "API_METADATA", fake_metadata)

    def fake_get_api_key(name: str) -> str | None:
        return None

    monkeypatch.setattr(main_module, "_get_api_key", fake_get_api_key)

    main_module.main(user_input=["8.8.8.8"], query_apis=["fakeprovider"], output_format="none")

    assert "No implementation found for fakeprovider" in capsys.readouterr().out
    assert len(display_calls) == 1


def test_main_runs_provider_in_thread(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_calls = _install_provider_stub(monkeypatch, "abstractapicom", api_key="k")

    main_module.main(user_input=["8.8.8.8"], query_apis=["abstractapicom"], output_format="none")

    assert len(provider_calls) == 1
    call = provider_calls[0]
    assert call["api_name"] == "abstractapicom"
    assert call["api_display_name"] == API_METADATA["abstractapicom"]["api_display_name"]
    assert call["ip_addresses"] == [GOOGLE_DNS]
    assert call["rate_limits"] == API_METADATA["abstractapicom"]["rate_limits"]
    assert call["api_key"] == "k"
    assert isinstance(call["db_conn"], sqlite3.Connection)
    assert len(display_calls) == 1


def test_main_clipboard_ips_accepted(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(main_module, "parse_clipboard", lambda: ["8.8.8.8"])

    def fake_ask_yn(question: str, *, true: str = "y") -> bool:
        assert true == "n"
        return False

    monkeypatch.setattr(main_module, "ask_yn", fake_ask_yn)

    main_module.main(user_input=[], query_apis=[], output_format="table")

    assert "Found in clipboard: ['8.8.8.8']" in capsys.readouterr().out
    assert display_calls[0]["ip_addresses"] == [GOOGLE_DNS]


def test_main_clipboard_ips_declined(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main_module, "parse_clipboard", lambda: ["8.8.8.8"])

    def fake_ask_yn(question: str, *, true: str = "y") -> bool:
        return True

    monkeypatch.setattr(main_module, "ask_yn", fake_ask_yn)

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(user_input=[], query_apis=[], output_format="table")

    assert "No IP addresses supplied" in str(excinfo.value)
    assert display_calls == []


def test_main_empty_clipboard_exits(
    tmp_db_path: str,
    display_calls: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main_module, "parse_clipboard", lambda: [])

    with pytest.raises(SystemExit) as excinfo:
        main_module.main(user_input=[], query_apis=[], output_format="table")

    assert "No IP addresses supplied and none detected in clipboard." in str(excinfo.value)
    assert display_calls == []


# --- cli() ---


def _install_main_recorder(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    recorded: dict[str, Any] = {}

    def fake_main(
        *, user_input: list[str], query_apis: list[str], output_format: str = "table"
    ) -> None:
        recorded["user_input"] = user_input
        recorded["query_apis"] = query_apis
        recorded["output_format"] = output_format

    monkeypatch.setattr(main_module, "main", fake_main)
    return recorded


def test_cli_no_args_expands_all_apis(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info"])

    main_module.cli()

    assert recorded["user_input"] == []
    assert recorded["query_apis"] == list(API_METADATA.keys())
    assert recorded["output_format"] == "table"


def test_cli_positional_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "8.8.8.8", "1.1.1.1"])

    main_module.cli()

    assert recorded["user_input"] == ["8.8.8.8", "1.1.1.1"]


def test_cli_named_ips_take_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "9.9.9.9", "--ip", "8.8.8.8"])

    main_module.cli()

    assert recorded["user_input"] == ["8.8.8.8"]


def test_cli_api_bulk_expands_bulk_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--api", "bulk"])

    main_module.cli()

    expected = [name for name, metadata in API_METADATA.items() if metadata["allows_bulk"]]
    assert expected  # sanity: config defines at least one bulk provider
    assert recorded["query_apis"] == expected


def test_cli_api_none_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--api", "none"])

    main_module.cli()

    assert recorded["query_apis"] == []


def test_cli_api_specific_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--api", "abuseipdbcom"])

    main_module.cli()

    assert recorded["query_apis"] == ["abuseipdbcom"]


def test_cli_format_rawjson(monkeypatch: pytest.MonkeyPatch) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--format", "rawjson"])

    main_module.cli()

    assert recorded["output_format"] == "rawjson"


def test_cli_invalid_format_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--format", "bogus"])

    with pytest.raises(SystemExit) as excinfo:
        main_module.cli()

    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert recorded == {}


def test_cli_invalid_api_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    recorded = _install_main_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["ip_info", "--api", "nosuchapi"])

    with pytest.raises(SystemExit) as excinfo:
        main_module.cli()

    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
    assert recorded == {}
