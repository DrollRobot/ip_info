"""Unit tests for the credential-backend dispatcher.

Fake backends are injected through the same importlib-by-name mechanism the
dispatcher uses in production (a module registered in sys.modules), so these
tests also prove the convention contract.

Deliberately free of any concrete backend: the dispatcher works with any
``*_backend.py`` module, and this file is deleted together with the whole
secret-storage machinery (``[features].secret_storage``), never with an
individual backend. The backends have their own test modules, deleted with
them.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from ip_info.config import schema, secrets
from ip_info.config.resolve import resolve_settings
from ip_info.config.schema import APP_NAME, CLI_NAME, ENV_PREFIX, ConfigError
from tests._config_test_object import (
    OptionalSecretTestObject,
    SecretTestObject,
    pin_prompt_policy,
)

pytestmark = pytest.mark.unit

# The project's own policy, read at import, before _prompt_policy replaces it.
_PROJECT_POLICY = schema.CREDENTIAL_BACKEND


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip this package's env vars so the env layer cannot shadow backends."""
    import os

    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def _prompt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the dispatcher, not the project's CREDENTIAL_BACKEND choice."""
    pin_prompt_policy(monkeypatch)


def _install_fake_backend(
    monkeypatch: pytest.MonkeyPatch, name: str = "fake", **attributes: Any
) -> types.ModuleType:
    """Register a fake ``<name>_backend`` module the dispatcher can import."""
    module = types.ModuleType(f"ip_info.config.{name}_backend")
    for attr, value in attributes.items():
        setattr(module, attr, value)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    return module


# --- schema policy -------------------------------------------------------------------
def test_credential_backend_policy_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    """The schema's CREDENTIAL_BACKEND must name a policy or an available backend.

    A schema check, but it needs the dispatcher to know which backends exist,
    so it lives here and is deleted with the secret-storage machinery. It is
    the one test about the project's own value, so it puts that value back.
    """
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", _PROJECT_POLICY)
    assert secrets.schema_backend_policy() in {"none", "prompt", *secrets.available_backends()}


# --- dispatcher ----------------------------------------------------------------------


def test_get_secret_routes_to_selected_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def fake_get(key: str, service: str, config: dict[str, Any]) -> str:
        calls.append((key, service, config))
        return "value"

    _install_fake_backend(monkeypatch, get=fake_get)
    config = {"credential_backend": "fake", "token_secret_name": "token", "extra": 1}
    assert secrets.get_secret("token", "prof", config) == "value"
    assert calls == [("token", f"{APP_NAME}:prof", config)]


def test_service_name_scopes_by_profile() -> None:
    assert secrets.service_name(None) == APP_NAME
    assert secrets.service_name("contoso") == f"{APP_NAME}:contoso"


def test_backend_name_has_no_default() -> None:
    """Which backend stores secrets is the user's choice; the code names none."""
    assert secrets.backend_name({}) is None
    assert secrets.backend_name({"credential_backend": "keyvault"}) == "keyvault"


def test_backend_name_rejects_non_string() -> None:
    with pytest.raises(ConfigError, match="must be a non-empty string"):
        secrets.backend_name({"credential_backend": 3})


def test_get_secret_without_backend_skips_the_layer() -> None:
    """No credential_backend configured: nothing stored, nothing imported."""
    assert secrets.get_secret("token", None, {}) is None


@pytest.mark.parametrize("operation", ["set", "delete"])
def test_writes_without_backend_fail_loudly(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    """Secret writes need an explicit user backend choice; the error names it."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)

    def write() -> None:
        if operation == "set":
            secrets.set_secret("token", "s", None, {})
        else:
            secrets.delete_secret("token", None, {})

    with pytest.raises(ConfigError) as excinfo:
        write()
    message = str(excinfo.value)
    assert "no credential_backend is configured" in message
    assert f"{CLI_NAME} set credential_backend" in message
    assert "fake" in message  # the available backends are listed


def test_missing_backend_module_is_actionable() -> None:
    with pytest.raises(ConfigError, match=r"no such backend exists.*Available backends"):
        secrets.get_secret("token", None, {"credential_backend": "nope"})


def test_set_secret_routes_to_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    stored: dict[str, str] = {}
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: stored.get(key),
        set=lambda key, value, service, config: stored.__setitem__(key, value),
        delete=lambda key, service, config: stored.__delitem__(key),
    )
    config = {"credential_backend": "fake", "token_secret_name": "token"}
    secrets.set_secret("token", "s", None, config)
    assert secrets.get_secret("token", None, config) == "s"
    secrets.delete_secret("token", None, config)
    assert secrets.get_secret("token", None, config) is None


def test_read_only_backend_rejects_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: None,
        READ_ONLY_HINT="update it at the source",
    )
    config = {"credential_backend": "fake"}
    with pytest.raises(ConfigError, match=r"read-only.*update it at the source"):
        secrets.set_secret("token", "s", None, config)
    with pytest.raises(ConfigError, match="read-only"):
        secrets.delete_secret("token", None, config)


# --- storage names -------------------------------------------------------------------


def test_storage_name_reads_config() -> None:
    assert secrets.storage_name("token", {"token_secret_name": "kv-token"}) == "kv-token"


def test_storage_name_missing_is_actionable() -> None:
    """No <field>_secret_name in config.toml: loud error, never a fallback."""
    with pytest.raises(ConfigError, match="'token_secret_name' is not set"):
        secrets.storage_name("token", {})


def test_storage_name_rejects_bad_value() -> None:
    with pytest.raises(ConfigError, match="non-empty string"):
        secrets.storage_name("token", {"token_secret_name": ""})
    with pytest.raises(ConfigError, match="non-empty string"):
        secrets.storage_name("token", {"token_secret_name": 3})


def test_secret_name_key_and_keys_and_help() -> None:
    assert secrets.secret_name_key("token") == "token_secret_name"
    assert secrets.secret_name_keys(["token"]) == frozenset({"token_secret_name"})
    help_map = secrets.secret_name_help({"token": None, "apikey": "kv-api"})
    assert "default: 'token'" in help_map["token_secret_name"]
    assert "default: 'kv-api'" in help_map["apikey_secret_name"]


def test_dispatch_uses_storage_name_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """The backend only ever sees the storage name, never the field name."""
    stored: dict[str, str] = {}
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: stored.get(key),
        set=lambda key, value, service, config: stored.__setitem__(key, value),
        delete=lambda key, service, config: stored.__delitem__(key),
    )
    config = {"credential_backend": "fake", "token_secret_name": "kv-token"}
    secrets.set_secret("token", "s", None, config)
    assert stored == {"kv-token": "s"}
    assert secrets.get_secret("token", None, config) == "s"
    secrets.delete_secret("token", None, config)
    assert stored == {}


def test_dispatch_missing_storage_name_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Backend configured but no storage name in config.toml: loud error."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: "v")
    with pytest.raises(ConfigError, match="'token_secret_name' is not set"):
        secrets.get_secret("token", None, {"credential_backend": "fake"})


def test_optional_secret_without_storage_name_is_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """An optional secret with no storage name is None; the backend is never asked."""

    def explode(key: str, service: str, config: dict[str, Any]) -> str:
        raise AssertionError("the backend must not be asked for an unnamed optional secret")

    _install_fake_backend(monkeypatch, get=explode)
    config = {"credential_backend": "fake"}
    assert secrets.get_secret("extra", None, config, optional=True) is None


def test_optional_secret_with_storage_name_reads_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    store = {"kv-extra": "s"}
    _install_fake_backend(monkeypatch, get=lambda key, service, config: store.get(key))
    config = {"credential_backend": "fake", "extra_secret_name": "kv-extra"}
    assert secrets.get_secret("extra", None, config, optional=True) == "s"


def test_reserved_config_passes_secret_name_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)
    config = {"credential_backend": "fake", "token_secret_name": "top", "name": "n"}
    profile_values = {"token_secret_name": "prof"}
    merged = secrets.reserved_config(config, profile_values)
    assert merged == {"credential_backend": "fake", "token_secret_name": "prof"}


# --- schema backend policy -----------------------------------------------------------


def test_schema_backend_policy_rejects_unknown_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "bogus")
    with pytest.raises(ConfigError, match="CREDENTIAL_BACKEND"):
        secrets.schema_backend_policy()


def test_backend_name_falls_back_to_schema_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """A backend-name policy is the default; config.toml still overrides it."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)
    _install_fake_backend(monkeypatch, name="other", get=lambda key, service, config: None)
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "fake")
    assert secrets.backend_name({}) == "fake"
    assert secrets.backend_name({"credential_backend": "other"}) == "other"


def test_none_policy_disables_secret_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    """'none': no backend, no reserved keys, loud writes naming the policy."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "none")
    assert secrets.backend_name({}) is None
    assert secrets.reserved_key_help() == {}
    assert secrets.reserved_profile_keys() == frozenset()
    assert secrets.secret_name_keys(["token"]) == frozenset()
    assert secrets.reserved_config({"credential_backend": "fake"}, {}) == {}
    with pytest.raises(ConfigError, match="CREDENTIAL_BACKEND is 'none'"):
        secrets.set_secret("token", "s", None, {})


# --- read-only detection -------------------------------------------------------------


def test_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: None,
        set=lambda key, value, service, config: None,
    )
    _install_fake_backend(
        monkeypatch,
        name="frozen",
        get=lambda key, service, config: None,
        READ_ONLY_HINT="see the vault",
    )
    assert secrets.is_read_only({}) is False  # no backend selected
    assert secrets.is_read_only({"credential_backend": "fake"}) is False
    assert secrets.is_read_only({"credential_backend": "frozen"}) is True


def test_read_only_notice_names_backend_and_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_backend(
        monkeypatch,
        name="frozen",
        get=lambda key, service, config: None,
        READ_ONLY_HINT="see the vault",
    )
    notice = secrets.read_only_notice({"credential_backend": "frozen"})
    assert "'frozen'" in notice
    assert "read-only" in notice
    assert "see the vault" in notice
    with pytest.raises(ConfigError, match="No credential backend is selected"):
        secrets.read_only_notice({})


# --- backend discovery and reserved keys ---------------------------------------------


def test_available_backends_sees_injected_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module registered under the naming convention is a usable backend."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)
    assert "fake" in secrets.available_backends()


def test_reserved_keys_come_from_the_backends(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each backend's RESERVED_KEYS joins the reserved set while it exists."""
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: None,
        RESERVED_KEYS={"fake_url": "Where the fake backend lives"},
    )
    reserved = secrets.reserved_profile_keys()
    assert "credential_backend" in reserved
    assert "fake_url" in reserved
    assert secrets.reserved_key_help()["fake_url"] == "Where the fake backend lives"
    assert secrets.backend_reserved_keys("fake") == {"fake_url": "Where the fake backend lives"}


def test_backend_without_reserved_keys_declares_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_backend(monkeypatch, get=lambda key, service, config: None)
    assert secrets.backend_reserved_keys("fake") == {}


def test_reserved_config_merges_profile_over_top_level(monkeypatch: pytest.MonkeyPatch) -> None:
    """Top-level reserved keys are shared fallbacks; the profile table wins."""
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: None,
        RESERVED_KEYS={"fake_url": "help"},
    )
    config = {"credential_backend": "fake", "fake_url": "top", "name": "not-reserved"}
    profile_values = {"fake_url": "prof"}
    merged = secrets.reserved_config(config, profile_values)
    assert merged == {"credential_backend": "fake", "fake_url": "prof"}


# --- resolver integration ------------------------------------------------------------


@pytest.mark.integration
def test_resolver_pulls_secret_from_profile_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Full stack: config file selects the backend, dispatcher imports it."""
    seen: list[tuple[str, str, dict[str, Any]]] = []

    def fake_get(key: str, service: str, config: dict[str, Any]) -> str:
        seen.append((key, service, config))
        return "from-backend"

    _install_fake_backend(monkeypatch, get=fake_get)
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
        credential_backend = "keyring"
        default_profile = "a"

        [profiles.a]
        name = "n"
        credential_backend = "fake"
        token_secret_name = "token"
        """,
        encoding="utf-8",
    )
    settings: SecretTestObject = resolve_settings(SecretTestObject, config_path=config_path)
    assert settings.token == "from-backend"  # noqa: S105
    # Profile-scoped service; profile's credential_backend overrode the top level.
    assert seen == [
        ("token", f"{APP_NAME}:a", {"credential_backend": "fake", "token_secret_name": "token"})
    ]


@pytest.mark.integration
def test_resolver_looks_up_secret_under_custom_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A <field>_secret_name override reaches the backend as the lookup key."""
    store = {"kv-token": "from-backend"}
    _install_fake_backend(monkeypatch, get=lambda key, service, config: store.get(key))
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'name = "n"\ncredential_backend = "fake"\ntoken_secret_name = "kv-token"\n',
        encoding="utf-8",
    )
    settings: SecretTestObject = resolve_settings(SecretTestObject, config_path=config_path)
    assert settings.token == "from-backend"  # noqa: S105


@pytest.mark.integration
def test_resolver_missing_secret_name_is_actionable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Backend configured but no <field>_secret_name in config.toml: loud error."""
    _install_fake_backend(monkeypatch, get=lambda key, service, config: "v")
    config_path = tmp_path / "config.toml"
    config_path.write_text('name = "n"\ncredential_backend = "fake"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="'token_secret_name' is not set"):
        resolve_settings(SecretTestObject, config_path=config_path)


@pytest.mark.integration
def test_resolver_accepts_backend_declared_keys_in_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A backend's RESERVED_KEYS are legal config.toml keys while it exists."""
    _install_fake_backend(
        monkeypatch,
        get=lambda key, service, config: config["fake_url"],
        RESERVED_KEYS={"fake_url": "help"},
    )
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        'name = "n"\ncredential_backend = "fake"\ntoken_secret_name = "token"\n'
        'fake_url = "https://x.invalid/"\n',
        encoding="utf-8",
    )
    settings: SecretTestObject = resolve_settings(SecretTestObject, config_path=config_path)
    assert settings.token == "https://x.invalid/"  # noqa: S105


@pytest.mark.integration
def test_resolver_optional_secret_unnamed_is_none_and_named_reads_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Backend configured: an unnamed optional secret is None, a named one is read."""
    store = {"token": "tok", "kv-extra": "from-backend"}
    _install_fake_backend(monkeypatch, get=lambda key, service, config: store.get(key))
    config_path = tmp_path / "config.toml"
    base = 'name = "n"\ncredential_backend = "fake"\ntoken_secret_name = "token"\n'
    config_path.write_text(base, encoding="utf-8")
    settings: OptionalSecretTestObject = resolve_settings(
        OptionalSecretTestObject, config_path=config_path
    )
    assert settings.extra is None

    config_path.write_text(base + 'extra_secret_name = "kv-extra"\n', encoding="utf-8")
    settings = resolve_settings(OptionalSecretTestObject, config_path=config_path)
    assert settings.extra == "from-backend"
