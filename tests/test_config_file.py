"""Unit tests for config.toml reading and validation in config/file.py.

Mostly independent of the secret-storage machinery: the validation rules
themselves know nothing about it, so the bulk of this file runs against the
secret-free test object and keeps passing in a project that removed the
machinery. The few cases that assert on the reserved backend keys (which the
machinery owns) carry the requires_secret_storage skip marker; the cases
about secret values in the file use SecretTestObject and need no machinery.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from ip_info.config import file as config_file
from ip_info.config.schema import ConfigError
from tests._config_test_object import (
    ConfigTestObject,
    SecretTestObject,
    block_secrets_module,
    pin_prompt_policy,
    requires_secret_storage,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _prompt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the validation rules, not the project's CREDENTIAL_BACKEND choice."""
    pin_prompt_policy(monkeypatch)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _load(tmp_path: Path, text: str) -> tuple[dict[str, Any], Path]:
    path = _write(tmp_path, text)
    document = config_file.read_config(path)
    assert document is not None
    return document, path


# --- read_config ---------------------------------------------------------------------


def test_read_config_missing_file_returns_none(tmp_path: Path) -> None:
    assert config_file.read_config(tmp_path / "config.toml") is None


def test_read_config_malformed_toml_raises(tmp_path: Path) -> None:
    path = _write(tmp_path, "name = ")
    with pytest.raises(ConfigError, match="Malformed TOML"):
        config_file.read_config(path)


# --- validate_config -----------------------------------------------------------------


def test_validate_accepts_full_valid_document(tmp_path: Path) -> None:
    document, path = _load(
        tmp_path,
        """
        name = "top"
        default_profile = "a"

        [profiles.a]
        name = "prof"
        count = 7
        """,
    )
    config_file.validate_config(document, ConfigTestObject, path)


@requires_secret_storage
def test_validate_accepts_backend_reserved_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Reserved keys come from the secret machinery, not from this module."""
    module = types.ModuleType("ip_info.config.fake_backend")
    module.RESERVED_KEYS = {"fake_url": "help"}  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, module.__name__, module)
    document, path = _load(
        tmp_path,
        """
        name = "top"
        credential_backend = "fake"

        [profiles.a]
        fake_url = "https://x.invalid/"
        """,
    )
    config_file.validate_config(document, ConfigTestObject, path)


def test_secret_reserved_keys_empty_when_machinery_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With secrets.py gone, no backend keys are legal and none leak through."""
    block_secrets_module(monkeypatch)
    assert config_file.secret_reserved_keys() == frozenset()
    document, path = _load(tmp_path, 'name = "top"\ncredential_backend = "keyring"\n')
    with pytest.raises(ConfigError, match="Unknown key 'credential_backend'"):
        config_file.validate_config(document, ConfigTestObject, path)


@requires_secret_storage
@pytest.mark.parametrize(
    "text",
    [
        'name = "top"\ntoken_secret_name = "kv-token"\n',
        'name = "top"\n[profiles.a]\ntoken_secret_name = "kv-token"\n',
    ],
    ids=["top-level", "profile"],
)
def test_validate_accepts_secret_name_keys(tmp_path: Path, text: str) -> None:
    """<secret>_secret_name is a legal reserved key while the machinery exists."""
    document, path = _load(tmp_path, text)
    config_file.validate_config(document, SecretTestObject, path)


def test_validate_rejects_secret_name_key_for_non_secret_field(tmp_path: Path) -> None:
    """Only secret fields have storage names; 'name' is a plain option."""
    document, path = _load(tmp_path, 'name_secret_name = "x"\n')
    with pytest.raises(ConfigError, match="Unknown key 'name_secret_name'"):
        config_file.validate_config(document, ConfigTestObject, path)


@requires_secret_storage
@pytest.mark.parametrize("value", ['""', "3"], ids=["empty", "non-string"])
def test_validate_rejects_bad_secret_name_value(tmp_path: Path, value: str) -> None:
    document, path = _load(tmp_path, f"token_secret_name = {value}\n")
    with pytest.raises(ConfigError, match="non-empty string"):
        config_file.validate_config(document, SecretTestObject, path)


def test_secret_name_keys_empty_when_machinery_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With secrets.py gone, storage-name keys are unknown keys."""
    block_secrets_module(monkeypatch)
    assert config_file.secret_name_keys(frozenset({"token"})) == frozenset()
    document, path = _load(tmp_path, 'name = "top"\ntoken_secret_name = "kv-token"\n')
    with pytest.raises(ConfigError, match="Unknown key 'token_secret_name'"):
        config_file.validate_config(document, ConfigTestObject, path)


def test_validate_rejects_unknown_top_level_key(tmp_path: Path) -> None:
    document, path = _load(tmp_path, 'nmae = "typo"\n')
    with pytest.raises(ConfigError, match="Unknown key 'nmae'"):
        config_file.validate_config(document, ConfigTestObject, path)


def test_validate_rejects_unknown_profile_key(tmp_path: Path) -> None:
    document, path = _load(tmp_path, '[profiles.a]\nnmae = "typo"\n')
    with pytest.raises(ConfigError, match=r"Unknown key 'nmae' in profile 'profiles\.a'"):
        config_file.validate_config(document, ConfigTestObject, path)


@pytest.mark.parametrize(
    "text",
    [
        'token = "leaked"\n',
        '[profiles.a]\ntoken = "leaked"\n',
    ],
    ids=["top-level", "profile"],
)
def test_validate_rejects_secret_values_in_file(tmp_path: Path, text: str) -> None:
    document, path = _load(tmp_path, text)
    with pytest.raises(ConfigError, match=r"Secrets must never be stored in config.toml"):
        config_file.validate_config(document, SecretTestObject, path)


def test_validate_rejects_non_string_default_profile(tmp_path: Path) -> None:
    document, path = _load(tmp_path, "default_profile = 3\n")
    with pytest.raises(ConfigError, match=r"'default_profile'.*must be a string"):
        config_file.validate_config(document, ConfigTestObject, path)


def test_validate_rejects_non_table_profiles(tmp_path: Path) -> None:
    document, path = _load(tmp_path, 'profiles = "oops"\n')
    with pytest.raises(ConfigError, match=r"'profiles'.*must be a table"):
        config_file.validate_config(document, ConfigTestObject, path)


def test_validate_rejects_non_table_profile_entry(tmp_path: Path) -> None:
    document, path = _load(tmp_path, '[profiles]\na = "oops"\n')
    with pytest.raises(ConfigError, match=r"Profile 'profiles\.a'.*must be a table"):
        config_file.validate_config(document, ConfigTestObject, path)


# --- profile_table -------------------------------------------------------------------


def test_profile_table_none_returns_empty(tmp_path: Path) -> None:
    document, path = _load(tmp_path, 'name = "top"\n')
    assert config_file.profile_table(document, None, path) == {}


def test_profile_table_returns_selected_profile(tmp_path: Path) -> None:
    document, path = _load(tmp_path, '[profiles.a]\nname = "prof"\n')
    assert config_file.profile_table(document, "a", path) == {"name": "prof"}


def test_profile_table_unknown_profile_lists_available(tmp_path: Path) -> None:
    document, path = _load(tmp_path, "[profiles.a]\n[profiles.b]\n")
    with pytest.raises(ConfigError, match=r"Profile 'c' not found.*a, b"):
        config_file.profile_table(document, "c", path)


def test_profile_table_no_profiles_at_all(tmp_path: Path) -> None:
    document, path = _load(tmp_path, 'name = "top"\n')
    with pytest.raises(ConfigError, match=r"Profile 'a' not found.*none defined"):
        config_file.profile_table(document, "a", path)
