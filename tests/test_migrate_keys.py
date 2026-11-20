"""Tests for scripts/migrate_keys.py: the one-time move of 1.x API keys.

The 1.x keyring is replaced by an in-memory stand-in, and the new layout by
an in-memory credential backend named 'fake' (registered in sys.modules, the
way the config system finds backends), selected by config.toml in a
temporary config folder. Nothing here touches a real keyring or the real
user config.
"""

import importlib
import os
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from ip_info.config import cli as config_cli
from ip_info.config.paths import CONFIG_DIR_ENV
from ip_info.config.schema import APP_NAME, ENV_PREFIX, ConfigError

pytestmark = pytest.mark.integration

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
OLD_KEY = "old-key-value"
OLD_ENTRY = ("ip_info-abuseipdbcom", "default")
NEW_ENTRY = (APP_NAME, "abuseipdbcom_api_key")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the config folder at tmp_path, with config.toml selecting the fake backend."""
    (tmp_path / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    monkeypatch.setenv(CONFIG_DIR_ENV, str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def new_store(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    """In-memory backend 'fake' for the new layout: ``(service, name) -> value``."""
    store: dict[tuple[str, str], str] = {}
    module: Any = types.ModuleType("ip_info.config.fake_backend")
    module.get = lambda key, service, config: store.get((service, key))
    module.set = lambda key, value, service, config: store.__setitem__((service, key), value)
    module.delete = lambda key, service, config: store.pop((service, key))
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return store


@pytest.fixture
def mk(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """The script as a module."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    return importlib.import_module("migrate_keys")


@pytest.fixture
def old_store(mk: types.ModuleType, monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    """In-memory stand-in for the 1.x keyring: ``(service, user) -> value``."""
    store: dict[tuple[str, str], str] = {}
    fake_keyring = types.SimpleNamespace(
        get_password=lambda service, user: store.get((service, user)),
        delete_password=lambda service, user: store.pop((service, user)),
    )
    monkeypatch.setattr(mk, "keyring", fake_keyring)
    return store


def _config(config_dir: Path) -> Any:
    return tomlkit.parse((config_dir / "config.toml").read_text(encoding="utf-8"))


# --- migrate_key ---


def test_missing_old_key_is_not_found(
    mk: types.ModuleType, old_store: dict[tuple[str, str], str], config_dir: Path
) -> None:
    assert mk.migrate_key("abuseipdbcom") == mk.NOT_FOUND
    assert "abuseipdbcom_api_key_secret_name" not in _config(config_dir)


def test_old_key_moves_and_old_copy_is_deleted(
    mk: types.ModuleType,
    config_dir: Path,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
) -> None:
    old_store[OLD_ENTRY] = OLD_KEY

    assert mk.migrate_key("abuseipdbcom") == mk.MOVED

    name = _config(config_dir)["abuseipdbcom_api_key_secret_name"]
    assert name == "abuseipdbcom_api_key"
    assert new_store == {NEW_ENTRY: OLD_KEY}
    assert old_store == {}


def test_existing_storage_name_is_kept(
    mk: types.ModuleType,
    config_dir: Path,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text(
        'credential_backend = "fake"\nabuseipdbcom_api_key_secret_name = "kv-abuse"\n',
        encoding="utf-8",
    )
    old_store[OLD_ENTRY] = OLD_KEY

    assert mk.migrate_key("abuseipdbcom") == mk.MOVED

    name = _config(config_dir)["abuseipdbcom_api_key_secret_name"]
    assert name == "kv-abuse"
    assert new_store == {(APP_NAME, "kv-abuse"): OLD_KEY}


def test_same_value_already_stored_only_removes_old_copy(
    mk: types.ModuleType,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
) -> None:
    old_store[OLD_ENTRY] = OLD_KEY
    new_store[NEW_ENTRY] = OLD_KEY

    assert mk.migrate_key("abuseipdbcom") == mk.ALREADY_THERE
    assert old_store == {}


def test_different_value_already_stored_is_a_conflict_and_keeps_both(
    mk: types.ModuleType,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
) -> None:
    old_store[OLD_ENTRY] = OLD_KEY
    new_store[NEW_ENTRY] = "other-value"

    assert mk.migrate_key("abuseipdbcom") == mk.CONFLICT
    assert old_store == {OLD_ENTRY: OLD_KEY}
    assert new_store == {NEW_ENTRY: "other-value"}


def test_key_that_does_not_read_back_keeps_old_copy(
    mk: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    old_store: dict[tuple[str, str], str],
) -> None:
    """A backend that drops writes must not cost the user their only copy."""
    monkeypatch.setattr(sys.modules["ip_info.config.fake_backend"], "set", lambda *args: None)
    old_store[OLD_ENTRY] = OLD_KEY

    with pytest.raises(ConfigError, match="did not read back"):
        mk.migrate_key("abuseipdbcom")
    assert old_store == {OLD_ENTRY: OLD_KEY}


def test_failed_config_write_is_an_error(
    mk: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    old_store: dict[tuple[str, str], str],
) -> None:
    monkeypatch.setattr(config_cli, "main", lambda argv: 1)
    old_store[OLD_ENTRY] = OLD_KEY

    with pytest.raises(ConfigError, match="Could not set abuseipdbcom_api_key_secret_name"):
        mk.migrate_key("abuseipdbcom")


def test_default_profile_stops_the_migration(
    mk: types.ModuleType, config_dir: Path, old_store: dict[tuple[str, str], str]
) -> None:
    (config_dir / "config.toml").write_text(
        'default_profile = "work"\n[profiles.work]\ncredential_backend = "fake"\n',
        encoding="utf-8",
    )
    old_store[OLD_ENTRY] = OLD_KEY

    with pytest.raises(ConfigError, match="selects default_profile 'work'"):
        mk.migrate_key("abuseipdbcom")


# --- main ---


def test_main_moves_every_found_key(
    mk: types.ModuleType,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_store[OLD_ENTRY] = OLD_KEY
    old_store[("ip_info-virustotalcom", "default")] = "vt-key"

    assert mk.main([]) == 0

    out = capsys.readouterr().out
    assert f"abuseipdbcom: {mk.MOVED}" in out
    assert f"virustotalcom: {mk.MOVED}" in out
    assert "ipinfoio" not in out  # providers without a 1.x key are not listed
    assert old_store == {}
    assert len(new_store) == 2


def test_main_with_no_old_keys_says_so(
    mk: types.ModuleType,
    old_store: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert mk.main([]) == 0
    assert "No 1.x keys found" in capsys.readouterr().out


def test_main_reports_conflicts_and_fails(
    mk: types.ModuleType,
    old_store: dict[tuple[str, str], str],
    new_store: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_store[OLD_ENTRY] = OLD_KEY
    new_store[NEW_ENTRY] = "other-value"

    assert mk.main([]) == 1

    captured = capsys.readouterr()
    assert f"abuseipdbcom: {mk.CONFLICT}" in captured.out
    assert "ip-info-config set-secret abuseipdbcom_api_key" in captured.err
    assert "'ip_info-abuseipdbcom'" in captured.err


def test_main_config_error_fails_and_keeps_old_copy(
    mk: types.ModuleType,
    config_dir: Path,
    old_store: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text('default_profile = "work"\n', encoding="utf-8")
    old_store[OLD_ENTRY] = OLD_KEY

    assert mk.main([]) == 1
    assert "ERROR:" in capsys.readouterr().err
    assert old_store == {OLD_ENTRY: OLD_KEY}


def test_main_rejects_arguments(mk: types.ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    assert mk.main(["--dry-run"]) == 2
    assert "takes no arguments" in capsys.readouterr().err


def test_main_reads_sys_argv_when_not_given(
    mk: types.ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    old_store: dict[tuple[str, str], str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["migrate_keys.py"])
    assert mk.main() == 0
