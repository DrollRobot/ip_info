"""Unit tests for the Settings schema conventions in config/schema.py.

These tests are generic over the schema: they iterate dataclasses.fields()
rather than naming specific options, so they keep passing when a downstream
repo replaces the FIXME example fields with its own.

Nothing here imports the secret-storage machinery, so the module type-checks
and runs in a project that deleted it. The one schema check that needs the
dispatcher -- that CREDENTIAL_BACKEND names a real policy or backend -- lives
in test_config_secrets.py, which is deleted along with it.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import get_type_hints

import pytest

from ip_info.config import file as config_file
from ip_info.config import paths, resolve
from ip_info.config.schema import (
    Settings,
    default_secret_name,
    field_default,
    field_help,
    is_optional_secret,
    is_required,
    is_secret,
    option,
    secret,
)

pytestmark = pytest.mark.unit

_LEAK_SENTINEL = "SENTINEL-LEAK-VALUE"


def _dummy_settings() -> Settings:
    """Build a Settings instance with dummy values, secrets set to a sentinel."""
    hints = get_type_hints(Settings)
    dummies: dict[type, object] = {str: "x", int: 1, float: 1.0, bool: True}
    values: dict[str, object] = {}
    for f in fields(Settings):
        if is_secret(f):
            values[f.name] = _LEAK_SENTINEL
        elif is_required(f):
            values[f.name] = dummies.get(hints[f.name], "x")
    return Settings(**values)  # type: ignore[arg-type]


def test_field_names_avoid_reserved_keys() -> None:
    """Option names must not collide with reserved config.toml or env-var names."""
    secret_names = frozenset(f.name for f in fields(Settings) if is_secret(f))
    reserved = (
        config_file.RESERVED_TOP_LEVEL_KEYS
        | config_file.secret_reserved_keys()  # credential_backend + backend keys
        | config_file.secret_name_keys(secret_names)  # <secret>_secret_name overrides
        | {"profile", "config_dir"}  # PROFILE_ENV / CONFIG_DIR_ENV suffixes
    )
    collisions = {f.name for f in fields(Settings)} & reserved
    assert not collisions


def test_secret_fields_disable_repr() -> None:
    for f in fields(Settings):
        if is_secret(f):
            assert f.repr is False, f"secret field {f.name!r} must set repr=False"


def test_secret_fields_never_have_default_values() -> None:
    """A default on a secret field is a secret value in source; never allowed.

    The one exception is an optional secret's None, which means "not set".
    """
    for f in fields(Settings):
        if is_optional_secret(f):
            assert f.default is None, f"optional secret {f.name!r} has a value in source"
        elif is_secret(f):
            assert is_required(f), f"secret field {f.name!r} has a value in source"


def test_secret_constructor_cannot_express_a_default_value() -> None:
    with pytest.raises(TypeError):
        secret(help="h", default_value="oops")  # type: ignore[call-arg]


def test_secret_constructor_rejects_empty_default_secret_name() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        secret(help="h", default_secret_name="")


def test_option_rejects_both_default_forms() -> None:
    with pytest.raises(ValueError, match="not both"):
        option(help="h", default_value=1, default_factory=list)


def test_constructors_set_field_conventions() -> None:
    @dataclass(frozen=True)
    class Local:
        token: str = secret(
            help="a secret",
            default_secret_name="kv-token",  # noqa: S106  (a name, not a secret)
        )
        plain: str = option(help="an option", default_value="v")

    token_field, plain_field = fields(Local)
    assert is_secret(token_field)
    assert token_field.repr is False
    assert is_required(token_field)
    assert default_secret_name(token_field) == "kv-token"
    assert not is_secret(plain_field)
    assert default_secret_name(plain_field) is None
    assert field_default(plain_field) == "v"
    assert field_help(token_field) == "a secret"


def test_optional_secret_constructor_defaults_to_none() -> None:
    @dataclass(frozen=True)
    class Local:
        token: str | None = secret(help="an optional secret", required=False)

    (token_field,) = fields(Local)
    assert is_secret(token_field)
    assert is_optional_secret(token_field)
    assert not is_required(token_field)
    assert token_field.repr is False
    assert field_default(token_field) is None
    assert Local().token is None


def test_is_optional_secret_is_false_for_required_secrets_and_options() -> None:
    @dataclass(frozen=True)
    class Local:
        token: str = secret(help="a required secret")
        plain: str = option(help="an option", default_value="v")

    token_field, plain_field = fields(Local)
    assert not is_optional_secret(token_field)
    assert not is_optional_secret(plain_field)


def test_secret_without_name_defaults_to_field_name_lookup() -> None:
    @dataclass(frozen=True)
    class Local:
        token: str = secret(help="a secret")

    (token_field,) = fields(Local)
    assert default_secret_name(token_field) is None
    assert is_required(token_field)


def test_repr_does_not_leak_secret_values() -> None:
    settings = _dummy_settings()
    assert _LEAK_SENTINEL not in repr(settings)
    assert _LEAK_SENTINEL not in str(settings)


def test_every_field_has_help_text() -> None:
    for f in fields(Settings):
        assert field_help(f), f"field {f.name!r} is missing help metadata"


def test_field_default_materializes_defaults_and_rejects_required() -> None:
    for f in fields(Settings):
        if is_required(f):
            with pytest.raises(ValueError, match="required"):
                field_default(f)
        elif is_optional_secret(f):
            assert field_default(f) is None
        else:
            assert field_default(f) is not None


def test_env_names_are_derived_from_one_prefix() -> None:
    """The profile and config-dir env vars share the schema's prefix."""
    assert resolve.PROFILE_ENV.endswith("_PROFILE")
    assert paths.CONFIG_DIR_ENV.endswith("_CONFIG_DIR")
    prefix = resolve.PROFILE_ENV.removesuffix("PROFILE")
    assert paths.CONFIG_DIR_ENV.removesuffix("CONFIG_DIR") == prefix
