"""Unit tests for the precedence engine in config/resolve.py.

All tests pass an explicit config_path under tmp_path and run against the
fixed test objects (tests/_config_test_object.py), so nothing here touches the
real user config directory or depends on the repo's FIXME example fields.

The precedence, coercion, and profile tests use the secret-free test object,
so they exercise the engine in a project that removed the secret-storage
machinery too. Tests that need a secret field use SecretTestObject and, when
they also need the machinery itself, carry the requires_secret_storage skip
marker.
"""

from __future__ import annotations

import os
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ip_info.config import resolve
from ip_info.config.resolve import (
    PROFILE_ENV,
    resolve_settings,
    resolve_with_sources,
)
from ip_info.config.schema import CLI_NAME, ENV_PREFIX, ConfigError
from tests._config_test_object import (
    ConfigTestObject,
    OptionalSecretTestObject,
    SecretTestObject,
    block_secrets_module,
    pin_prompt_policy,
    requires_secret_storage,
)

pytestmark = pytest.mark.unit

# No test here configures a credential_backend, and _prompt_policy removes the
# schema default, so the resolver never touches a real credential store: with
# no backend selected the secret layer is skipped by design (the old autouse
# get_secret stub is unnecessary).


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip all of this package's env vars so each test controls every layer."""
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def _prompt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the resolver, not the project's CREDENTIAL_BACKEND choice."""
    pin_prompt_policy(monkeypatch)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    return tmp_path / "config.toml"


def _resolve(config_path: Path, **kwargs: Any) -> ConfigTestObject:
    """Resolve the secret-free test object; the secret layer is never reached."""
    result: ConfigTestObject = resolve_settings(ConfigTestObject, config_path=config_path, **kwargs)
    return result


def _resolve_secret(config_path: Path, **kwargs: Any) -> SecretTestObject:
    """Resolve the test object carrying a required secret field."""
    result: SecretTestObject = resolve_settings(SecretTestObject, config_path=config_path, **kwargs)
    return result


def _write(config_path: Path, text: str) -> None:
    config_path.write_text(text, encoding="utf-8")


# --- zero-file paths -----------------------------------------------------------------


def test_env_only_run_with_no_file(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    """CI/headless: env vars alone produce a working run; defaults fill the rest."""
    monkeypatch.setenv(ENV_PREFIX + "NAME", "from-env")
    settings = _resolve(config_path)
    assert settings.name == "from-env"
    assert settings.count == 3
    assert settings.ratio == 0.5
    assert settings.flag is False
    assert settings.tags == []


@requires_secret_storage
def test_env_only_run_supplies_secrets(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    """A secret field resolves from its env var with no backend in play."""
    monkeypatch.setenv(ENV_PREFIX + "NAME", "from-env")
    monkeypatch.setenv(ENV_PREFIX + "TOKEN", "tok")
    settings = _resolve_secret(config_path)
    assert settings.name == "from-env"
    assert settings.token == "tok"  # noqa: S105


def test_missing_required_is_actionable(config_path: Path) -> None:
    with pytest.raises(ConfigError) as excinfo:
        _resolve(config_path)
    message = str(excinfo.value)
    assert "name" in message
    assert ENV_PREFIX + "NAME" in message
    assert f"{CLI_NAME} init" in message
    assert str(config_path) in message


@requires_secret_storage
def test_missing_secret_without_backend_names_the_choice(config_path: Path) -> None:
    """A missing secret with no backend configured points at picking one."""
    with pytest.raises(ConfigError) as excinfo:
        _resolve_secret(config_path)
    message = str(excinfo.value)
    assert "token" in message
    assert ENV_PREFIX + "TOKEN" in message
    assert "No credential_backend is configured" in message
    assert f"{CLI_NAME} set credential_backend" in message


@requires_secret_storage
def test_missing_secret_under_none_policy_points_at_env(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """Under the 'none' policy the error names env vars, not set-secret."""
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "none")
    with pytest.raises(ConfigError) as excinfo:
        _resolve_secret(config_path)
    message = str(excinfo.value)
    assert "CREDENTIAL_BACKEND is 'none'" in message
    assert "set-secret" not in message


# --- schema validation ---------------------------------------------------------------


def test_secret_field_with_default_value_is_rejected(config_path: Path) -> None:
    """A secret default is a secret value in source; the schema is rejected outright."""

    @dataclass(frozen=True)
    class BadSchema:
        token: str = field(default="oops", repr=False, metadata={"secret": True, "help": "h"})

    with pytest.raises(ConfigError, match="secret value in source"):
        resolve_settings(BadSchema, config_path=config_path)


def test_secret_field_with_repr_enabled_is_rejected(config_path: Path) -> None:
    @dataclass(frozen=True)
    class BadSchema:
        token: str = field(metadata={"secret": True, "help": "h"})

    with pytest.raises(ConfigError, match="repr=False"):
        resolve_settings(BadSchema, config_path=config_path)


def test_non_secret_with_default_secret_name_is_rejected(config_path: Path) -> None:
    @dataclass(frozen=True)
    class BadSchema:
        name: str = field(metadata={"help": "h", "default_secret_name": "kv-name"})

    with pytest.raises(ConfigError, match="is not secret"):
        resolve_settings(BadSchema, config_path=config_path)


def test_optional_secret_with_value_default_is_rejected(config_path: Path) -> None:
    """An optional secret's only legal default is None; the value is never echoed."""

    @dataclass(frozen=True)
    class BadSchema:
        token: str | None = field(
            default="oops-value",
            repr=False,
            metadata={"secret": True, "optional": True, "help": "h"},
        )

    with pytest.raises(ConfigError, match="secret value in source") as excinfo:
        resolve_settings(BadSchema, config_path=config_path)
    assert "oops-value" not in str(excinfo.value)


def test_optional_secret_without_default_is_rejected(config_path: Path) -> None:
    @dataclass(frozen=True)
    class BadSchema:
        token: str | None = field(
            repr=False, metadata={"secret": True, "optional": True, "help": "h"}
        )

    with pytest.raises(ConfigError, match="must have the default None"):
        resolve_settings(BadSchema, config_path=config_path)


def test_optional_secret_must_be_annotated_optional_str(config_path: Path) -> None:
    @dataclass(frozen=True)
    class BadSchema:
        token: str = field(
            default=None,  # type: ignore[assignment]
            repr=False,
            metadata={"secret": True, "optional": True, "help": "h"},
        )

    with pytest.raises(ConfigError, match=r"must be annotated 'str \| None'"):
        resolve_settings(BadSchema, config_path=config_path)


@pytest.mark.parametrize(
    ("tp", "expected"),
    [
        (str | None, True),
        # The old spelling is the point: older Pythons build it as a distinct type.
        (typing.Optional[str], True),  # noqa: UP045
        (str, False),
        (int | None, False),
        (str | int | None, False),
    ],
)
def test_is_optional_str(tp: Any, expected: bool) -> None:
    assert resolve._is_optional_str(tp) is expected


# --- optional secrets ----------------------------------------------------------------


@requires_secret_storage
def test_optional_secret_missing_everywhere_is_none(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """An optional secret no layer provides is None, with no error."""
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    monkeypatch.setenv(ENV_PREFIX + "TOKEN", "tok")
    settings, sources, _ = resolve_with_sources(OptionalSecretTestObject, config_path=config_path)
    assert settings.extra is None
    assert sources["extra"] == "not set"


@requires_secret_storage
def test_optional_secret_resolves_from_env(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    monkeypatch.setenv(ENV_PREFIX + "TOKEN", "tok")
    monkeypatch.setenv(ENV_PREFIX + "EXTRA", "from-env")
    settings, sources, _ = resolve_with_sources(OptionalSecretTestObject, config_path=config_path)
    assert settings.extra == "from-env"
    assert sources["extra"] == f"env:{ENV_PREFIX}EXTRA"


@requires_secret_storage
def test_optional_secret_override_is_type_checked_as_str(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    monkeypatch.setenv(ENV_PREFIX + "TOKEN", "tok")
    settings: OptionalSecretTestObject = resolve_settings(
        OptionalSecretTestObject, config_path=config_path, overrides={"extra": "ovr"}
    )
    assert settings.extra == "ovr"
    with pytest.raises(ConfigError, match="'extra' in overrides"):
        resolve_settings(OptionalSecretTestObject, config_path=config_path, overrides={"extra": 1})


@requires_secret_storage
def test_missing_required_secret_still_fails_beside_optional_one(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """Only the required secret is reported missing; the optional one is not."""
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    with pytest.raises(ConfigError) as excinfo:
        resolve_settings(OptionalSecretTestObject, config_path=config_path)
    message = str(excinfo.value)
    assert "Missing required configuration value(s): token." in message
    assert ENV_PREFIX + "EXTRA" not in message


# --- optional secret machinery -------------------------------------------------------


def test_no_secret_fields_resolves_without_secret_machinery(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """A schema with no secret fields runs with config/secrets.py deleted."""
    block_secrets_module(monkeypatch)
    _write(config_path, 'name = "n"\n')
    settings = _resolve(config_path)
    assert settings.name == "n"
    assert settings.count == 3


def test_secret_fields_with_machinery_removed_is_actionable(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """Secret fields left in the schema after removal fail loudly, not weirdly."""
    block_secrets_module(monkeypatch)
    _write(config_path, 'name = "n"\n')
    with pytest.raises(ConfigError, match=r"secret-storage machinery.*removed"):
        _resolve_secret(config_path)


def test_backend_keys_rejected_when_machinery_removed(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    """With secrets.py gone there are no reserved keys; leftovers fail loudly."""
    block_secrets_module(monkeypatch)
    _write(config_path, 'name = "n"\ncredential_backend = "keyring"\n')
    with pytest.raises(ConfigError, match="Unknown key 'credential_backend'"):
        _resolve(config_path)


# --- precedence ----------------------------------------------------------------------


def test_precedence_across_all_layers(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    """Peel layers off one by one; the next one down must win each time."""
    _write(
        config_path,
        """
        name = "top"
        default_profile = "a"

        [profiles.a]
        name = "prof"
        """,
    )

    monkeypatch.setenv(ENV_PREFIX + "NAME", "env")
    assert _resolve(config_path, overrides={"name": "ovr"}).name == "ovr"
    assert _resolve(config_path).name == "env"

    monkeypatch.delenv(ENV_PREFIX + "NAME")
    assert _resolve(config_path).name == "prof"

    _write(config_path, 'name = "top"\n')
    assert _resolve(config_path).name == "top"


def test_profile_values_override_top_level_fallbacks(config_path: Path) -> None:
    _write(
        config_path,
        """
        name = "top"
        count = 1

        [profiles.a]
        count = 2
        """,
    )
    settings = _resolve(config_path, profile="a")
    assert settings.name == "top"  # top-level fallback still applies
    assert settings.count == 2  # profile wins where both define a value


def test_override_type_is_checked(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    with pytest.raises(ConfigError, match="'count' in overrides"):
        _resolve(config_path, overrides={"count": "not-an-int"})


# --- profile selection ---------------------------------------------------------------


def test_profile_selection_order(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    _write(
        config_path,
        """
        default_profile = "c"

        [profiles.a]
        name = "from-a"
        [profiles.b]
        name = "from-b"
        [profiles.c]
        name = "from-c"
        """,
    )
    monkeypatch.setenv(PROFILE_ENV, "b")
    assert _resolve(config_path, profile="a").name == "from-a"  # arg beats env
    assert _resolve(config_path).name == "from-b"  # env beats default_profile
    monkeypatch.delenv(PROFILE_ENV)
    assert _resolve(config_path).name == "from-c"  # default_profile last


def test_unknown_profile_lists_available(config_path: Path) -> None:
    _write(config_path, '[profiles.a]\nname = "x"\n')
    with pytest.raises(ConfigError, match=r"Profile 'zz' not found.*a"):
        _resolve(config_path, profile="zz")


@pytest.mark.regression
def test_profiles_defined_but_none_selected_names_the_fix(config_path: Path) -> None:
    """Profiles exist but none is selected: the error says so, not just "missing"."""
    _write(config_path, '[profiles.b]\nname = "x"\n[profiles.a]\nname = "y"\n')
    with pytest.raises(ConfigError) as excinfo:
        _resolve(config_path)
    message = str(excinfo.value)
    assert "No profile selected" in message
    assert f"Profiles defined in {config_path}: a, b" in message
    assert "--profile" in message
    assert PROFILE_ENV in message
    assert f"{CLI_NAME} use" in message


def test_profile_requested_but_no_file(config_path: Path) -> None:
    with pytest.raises(ConfigError, match="no config file exists"):
        _resolve(config_path, profile="a")


# --- env-var coercion ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("env_name", "raw", "field_name", "expected"),
    [
        ("COUNT", "7", "count", 7),
        ("RATIO", "0.25", "ratio", 0.25),
        ("FLAG", "TRUE", "flag", True),
        ("FLAG", "false", "flag", False),
        ("TAGS", "a, b ,c", "tags", ["a", "b", "c"]),
        ("TAGS", "", "tags", []),
    ],
)
def test_env_coercion(
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
    env_name: str,
    raw: str,
    field_name: str,
    expected: object,
) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    monkeypatch.setenv(ENV_PREFIX + env_name, raw)
    assert getattr(_resolve(config_path), field_name) == expected


@pytest.mark.parametrize(
    ("env_name", "raw", "match"),
    [
        ("COUNT", "seven", "must be an integer"),
        ("RATIO", "fast", "must be a number"),
        ("FLAG", "yes", "must be 'true' or 'false'"),
    ],
)
def test_env_coercion_failures(
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
    env_name: str,
    raw: str,
    match: str,
) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    monkeypatch.setenv(ENV_PREFIX + env_name, raw)
    with pytest.raises(ConfigError, match=match):
        _resolve(config_path)


# --- file value typing ---------------------------------------------------------------


def test_file_type_mismatch_fails_loudly(
    monkeypatch: pytest.MonkeyPatch, config_path: Path
) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    _write(config_path, 'count = "seven"\n')
    with pytest.raises(ConfigError, match="'count' in the top level"):
        _resolve(config_path)


def test_file_bool_does_not_satisfy_int(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    _write(config_path, "count = true\n")
    with pytest.raises(ConfigError, match="'count' in the top level"):
        _resolve(config_path)


def test_file_int_fills_float_field(monkeypatch: pytest.MonkeyPatch, config_path: Path) -> None:
    monkeypatch.setenv(ENV_PREFIX + "NAME", "n")
    _write(config_path, "ratio = 1\n")
    settings = _resolve(config_path)
    assert settings.ratio == 1.0
    assert isinstance(settings.ratio, float)


def test_secret_in_file_is_rejected(config_path: Path) -> None:
    _write(config_path, 'token = "leaked"\n')
    with pytest.raises(ConfigError, match=r"Secrets must never be stored"):
        _resolve_secret(config_path)


# --- public entry point --------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.smoke
def test_load_settings_env_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """load_settings() works against the real schema with env vars alone.

    Generic over the schema so it keeps passing when downstream repos replace
    the FIXME example fields.
    """
    from dataclasses import fields
    from typing import get_type_hints

    from ip_info.config import Settings, load_settings
    from ip_info.config.paths import CONFIG_DIR_ENV
    from ip_info.config.schema import is_required

    monkeypatch.setenv(CONFIG_DIR_ENV, str(tmp_path))
    dummies = {str: "x", int: "1", float: "1.0", bool: "true"}
    hints = get_type_hints(Settings)
    for f in fields(Settings):
        if is_required(f):
            monkeypatch.setenv(ENV_PREFIX + f.name.upper(), dummies.get(hints[f.name], "x"))
    assert isinstance(load_settings(), Settings)
