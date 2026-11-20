"""config.toml reading, validation, and profile-table access.

Reads use stdlib ``tomllib``. (The comment-preserving write path used by the
config CLI lives in ``cli.py`` and uses ``tomlkit``; nothing here writes.)

File shape::

    # Single-tenant (simplest form): bare top-level keys, no profile syntax.
    tenant_id = "..."

    # Multi-tenant: profiles. Top-level keys act as shared fallbacks.
    default_profile = "contoso"

    [profiles.contoso]
    tenant_id = "..."

Beyond the schema's own option names, the secret-backend machinery
(``secrets.py`` and the ``*_backend.py`` modules) reserves keys of its own:
``credential_backend``, whatever each backend declares, and one
``<field>_secret_name`` per secret field (the backend storage-name override,
a non-empty string). This module learns them from ``secrets.py`` at
validation time and knows none of them itself. When the secret machinery has
been deleted -- or the schema's ``CREDENTIAL_BACKEND`` policy is ``"none"``
-- no such keys are legal.

Validation is strict and fails loudly (see AGENTS.md): unknown keys, secret
values stored in the file, or malformed tables all raise
:class:`~ip_info.config.schema.ConfigError` naming the problem.
"""

from __future__ import annotations

import importlib
import tomllib
from dataclasses import fields
from pathlib import Path
from typing import Any, cast

from ip_info.config.schema import ConfigError, is_secret

# Keys legal only at the top level of the file.
RESERVED_TOP_LEVEL_KEYS = frozenset({"default_profile", "profiles"})


def secret_reserved_keys() -> frozenset[str]:
    """Return the profile keys reserved by the secret-backend machinery.

    Asks ``secrets.py`` (imported lazily, so this module never depends on it)
    for ``credential_backend`` plus every available backend's declared keys.
    When the secret machinery has been deleted from the package, there are no
    reserved profile keys and any such key in config.toml fails validation.

    Returns:
        The reserved key names, or an empty set when ``secrets.py`` is absent.
    """
    module_name = f"{__package__}.secrets"
    try:
        secrets = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise  # secrets.py exists but something it imports is missing
        return frozenset()
    return cast("frozenset[str]", secrets.reserved_profile_keys())


def secret_name_keys(secret_names: frozenset[str]) -> frozenset[str]:
    """Return the legal ``<field>_secret_name`` keys for *secret_names*.

    Asks ``secrets.py`` (imported lazily, like :func:`secret_reserved_keys`)
    so this module never hardcodes the suffix. Empty when the machinery is
    deleted or the schema's ``CREDENTIAL_BACKEND`` policy is ``"none"``.

    Args:
        secret_names: The schema's secret field names.

    Returns:
        The reserved storage-name key names, or an empty set.
    """
    module_name = f"{__package__}.secrets"
    try:
        secrets = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise  # secrets.py exists but something it imports is missing
        return frozenset()
    return cast("frozenset[str]", secrets.secret_name_keys(secret_names))


def read_config(path: Path) -> dict[str, Any] | None:
    """Read and parse *path* as TOML.

    Args:
        path: Location of the config file.

    Returns:
        The parsed document, or None when the file does not exist (callers
        distinguish "no file" from "empty file" for error messages).

    Raises:
        ConfigError: If the file exists but is not valid TOML.
    """
    if not path.exists():
        return None
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Malformed TOML in {path}: {exc}") from exc


def validate_config(config: dict[str, Any], schema: type[Any], path: Path) -> None:
    """Validate the parsed config *document* against the settings *schema*.

    Checks performed:

    - Every top-level key is a known non-secret option, a reserved top-level
      key, or a reserved profile key (the top level doubles as the unnamed
      profile in single-tenant mode).
    - Every profile-table key is a known non-secret option or a reserved
      profile key.
    - No secret-classified field name appears anywhere in the file.
    - Every ``<field>_secret_name`` storage-name override is a non-empty
      string naming one of *schema*'s secret fields.
    - ``default_profile`` is a string; ``profiles`` is a table of tables.

    Args:
        config: Parsed TOML document.
        schema: Settings dataclass whose fields define the known options.
        path: File path, used in error messages only.

    Raises:
        ConfigError: On the first violation found, naming the offending key.
    """
    option_names = {f.name for f in fields(schema)}
    secret_names = frozenset(f.name for f in fields(schema) if is_secret(f))
    plain_names = option_names - secret_names
    name_keys = secret_name_keys(secret_names)
    reserved_profile_keys = secret_reserved_keys() | name_keys

    def check_keys(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
        for key in table:
            if key in secret_names:
                raise ConfigError(
                    f"Secret value {key!r} found in {where} of {path}. Secrets must never be "
                    "stored in config.toml; store them with the config CLI's set-secret command."
                )
            if key not in plain_names and key not in allowed:
                valid = ", ".join(sorted(plain_names | allowed))
                raise ConfigError(f"Unknown key {key!r} in {where} of {path}. Valid keys: {valid}.")
            if key in name_keys:
                value = table[key]
                if not isinstance(value, str) or not value:
                    raise ConfigError(
                        f"{key!r} in {where} of {path} must be a non-empty string "
                        f"(a backend storage name), got {value!r}."
                    )

    check_keys(config, RESERVED_TOP_LEVEL_KEYS | reserved_profile_keys, "the top level")

    default_profile = config.get("default_profile")
    if default_profile is not None and not isinstance(default_profile, str):
        raise ConfigError(
            f"'default_profile' in {path} must be a string, got {type(default_profile).__name__}."
        )

    profiles = config.get("profiles")
    if profiles is None:
        return
    if not isinstance(profiles, dict):
        raise ConfigError(f"'profiles' in {path} must be a table of profile tables.")
    for name, table in profiles.items():
        if not isinstance(table, dict):
            raise ConfigError(
                f"Profile 'profiles.{name}' in {path} must be a table, got {type(table).__name__}."
            )
        check_keys(table, reserved_profile_keys, f"profile 'profiles.{name}'")


def profile_table(config: dict[str, Any], name: str | None, path: Path) -> dict[str, Any]:
    """Return the table for profile *name*, or an empty dict when *name* is None.

    Args:
        config: Parsed TOML document.
        name: Profile name to select, or None for bare top-level mode.
        path: File path, used in error messages only.

    Returns:
        The profile's table. Values from it override bare top-level keys.

    Raises:
        ConfigError: If *name* is given but no such profile exists.
    """
    if name is None:
        return {}
    profiles = config.get("profiles")
    if not isinstance(profiles, dict) or name not in profiles:
        available = sorted(profiles) if isinstance(profiles, dict) else []
        listing = ", ".join(available) if available else "none defined"
        raise ConfigError(f"Profile {name!r} not found in {path}. Available profiles: {listing}.")
    # validate_config has already enforced that every profile value is a table.
    return cast("dict[str, Any]", profiles[name])
