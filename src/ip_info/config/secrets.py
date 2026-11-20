"""Credential-backend dispatcher.

Routes secret reads/writes to whichever backend a profile selects with its
``credential_backend`` key. Dispatch is by naming convention --
``credential_backend = "<name>"`` lazily imports
``ip_info.config.<name>_backend`` -- so this module never names
a concrete backend and deleting a backend file removes it completely without
touching this file.

Whether a *default* backend exists is the schema author's choice, declared as
``CREDENTIAL_BACKEND`` in ``schema.py`` (see :func:`schema_backend_policy`):

- ``"none"``: this package stores no secrets. Reads skip the backend layer
  (environment variables still work), writes fail loudly, and every reserved
  backend key becomes illegal in config.toml.
- a backend name (e.g. ``"keyring"``): the default backend, used without
  prompting; a profile may still override it with ``credential_backend`` in
  config.toml.
- ``"prompt"``: no default. The user picks by setting ``credential_backend``
  in config.toml (via the config CLI). With no backend configured, secret
  reads simply skip the backend layer; secret writes fail loudly naming the
  available backends.

Secrets are stored under a storage NAME: the profile's
``<field>_secret_name`` key in config.toml, written by ``init`` and
``set-secret``. A missing name is a config error, never a fallback; for an
optional secret it means the secret is not set. Storage names are not
secrets, so config.toml is a legal home for them.

This module is itself optional. Nothing else in the config system imports it
at module scope, so when the settings schema marks no field ``secret`` the
whole secret-storage machinery -- this file plus every ``*_backend.py`` file
and their tests -- can be deleted without touching the rest of the package.

Backend module contract (structural, checked at call time):

- ``get(key, service, config) -> str | None``  -- required. Return the secret
  value, or None when the key is not stored.
- ``set(key, value, service, config) -> None`` -- optional. A backend without
  it is read-only; ``set_secret`` reports how to update the secret instead.
- ``delete(key, service, config) -> None``     -- optional, as above.
- ``RESERVED_KEYS: dict[str, str]``            -- optional. config.toml keys
  the backend consumes (beyond ``credential_backend``), mapped to help text;
  they become legal profile keys while the backend file exists.
- Third-party imports must live inside the functions that use them, so the
  module itself always imports (backend discovery imports every backend).

Where ``key`` is the *storage* name of the secret (the schema field name, or
the profile's ``<field>_secret_name`` override), ``service`` is the
profile-scoped namespace (``ip_info:<profile>``), and ``config``
is the merged reserved-key table for the active profile.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from collections.abc import Iterable, Mapping
from typing import Any, Protocol, cast

from ip_info.config import schema as _schema
from ip_info.config.schema import APP_NAME, CLI_NAME, ConfigError

# The reserved profile key selecting the backend. Whether a default exists is
# the schema's CREDENTIAL_BACKEND policy; the user can always pick (or, under
# a schema default, override) the backend here.
BACKEND_KEY = "credential_backend"

# Suffix of the reserved per-field keys overriding backend storage names:
# '<field>_secret_name' holds the name secret '<field>' is stored under in
# the backend (default: the field name itself).
SECRET_NAME_SUFFIX = "_secret_name"  # noqa: S105  (a key suffix, not a credential)

# schema.CREDENTIAL_BACKEND values that are policies, not backend names.
_POLICY_NONE = "none"
_POLICY_PROMPT = "prompt"

# Module-name suffix that marks a file in this package as a backend.
_BACKEND_SUFFIX = "_backend"

# This package's qualified name. Unlike ``__package__`` it is always a str,
# which keeps type checkers happy at the import_module call.
_PACKAGE = __name__.rpartition(".")[0]


class _CredentialBackend(Protocol):
    """Structural contract implemented by every ``<name>_backend`` module."""

    def get(self, key: str, service: str, config: Mapping[str, Any]) -> str | None: ...


def service_name(profile: str | None) -> str:
    """Return the backend namespace for *profile*.

    Namespacing by profile keeps multi-tenant secrets apart (e.g. two tenants
    both storing ``client_secret``).

    Args:
        profile: Active profile name, or None for bare top-level mode.

    Returns:
        ``ip_info:<profile>``, or just ``ip_info``
        when no profile is active.
    """
    return f"{APP_NAME}:{profile}" if profile else APP_NAME


def schema_backend_policy() -> str:
    """Return the schema's validated ``CREDENTIAL_BACKEND`` policy.

    A schema.py without the constant (predating it) is read as ``"prompt"``,
    which is exactly the pre-policy behavior.

    Returns:
        ``"none"``, ``"prompt"``, or an available backend name.

    Raises:
        ConfigError: When the constant names neither a policy nor an
            available backend.
    """
    policy = str(getattr(_schema, "CREDENTIAL_BACKEND", _POLICY_PROMPT))
    valid = {_POLICY_NONE, _POLICY_PROMPT, *available_backends()}
    if policy not in valid:
        raise ConfigError(
            f"schema.CREDENTIAL_BACKEND = {policy!r} is not valid. "
            f"Use one of: {', '.join(sorted(valid))}."
        )
    return policy


def secret_name_key(field_name: str) -> str:
    """Return the reserved key holding *field_name*'s backend storage name.

    Args:
        field_name: Schema field name of a secret.

    Returns:
        ``<field_name>_secret_name``.
    """
    return field_name + SECRET_NAME_SUFFIX


def secret_name_keys(secret_fields: Iterable[str]) -> frozenset[str]:
    """Return the legal ``<field>_secret_name`` keys for *secret_fields*.

    Empty under the ``"none"`` policy: with no secret storage there is
    nothing to name, and the keys are rejected by config validation.

    Args:
        secret_fields: Schema field names marked secret.

    Returns:
        The reserved storage-name key names.
    """
    if schema_backend_policy() == _POLICY_NONE:
        return frozenset()
    return frozenset(secret_name_key(name) for name in secret_fields)


def secret_name_help(secret_fields: Mapping[str, str | None]) -> dict[str, str]:
    """Return each ``<field>_secret_name`` key mapped to its help text.

    Args:
        secret_fields: Secret field names mapped to their
            ``default_secret_name`` (None: the field name is the default).

    Returns:
        ``{key: help text}``; empty under the ``"none"`` policy.
    """
    if schema_backend_policy() == _POLICY_NONE:
        return {}
    return {
        secret_name_key(name): (
            f"Backend storage name for secret {name!r} (default: {(default or name)!r})"
        )
        for name, default in secret_fields.items()
    }


def storage_name(key: str, config: Mapping[str, Any]) -> str:
    """Return the backend storage name for secret field *key*.

    Args:
        key: Schema field name of the secret.
        config: Merged reserved-key table for the active profile.

    Returns:
        The profile's ``<key>_secret_name`` value from config.toml.

    Raises:
        ConfigError: If the name is missing or not a non-empty string.
    """
    name = config.get(secret_name_key(key))
    if name is None:
        raise ConfigError(
            f"{secret_name_key(key)!r} is not set in config.toml. "
            f"Run '{CLI_NAME} init', or '{CLI_NAME} set {secret_name_key(key)} <name>'."
        )
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{secret_name_key(key)!r} must be a non-empty string, got {name!r}.")
    return name


def available_backends() -> list[str]:
    """Return the names of every backend module importable in this package.

    Discovered by naming convention: ``<name>_backend.py`` in this package is
    the backend ``<name>``. Deleting a backend file removes it from this
    list; adding one adds it, with no registration step. Modules already in
    ``sys.modules`` under the convention count too -- they are exactly as
    importable as files (tests inject in-memory backends this way).

    Returns:
        Sorted backend names (e.g. ``["keyring", "keyvault"]``).
    """
    package = importlib.import_module(_PACKAGE)
    names = {
        module.name
        for module in pkgutil.iter_modules(package.__path__)
        if module.name.endswith(_BACKEND_SUFFIX)
    }
    prefix = f"{_PACKAGE}."
    names.update(
        tail
        for qualified, module in sys.modules.items()
        if module is not None
        and qualified.startswith(prefix)
        and (tail := qualified.removeprefix(prefix)).endswith(_BACKEND_SUFFIX)
        and "." not in tail
    )
    return sorted(name[: -len(_BACKEND_SUFFIX)] for name in names)


def backend_reserved_keys(name: str) -> dict[str, str]:
    """Return backend *name*'s config keys mapped to their help text.

    Args:
        name: Backend name (e.g. ``"keyvault"``).

    Returns:
        The backend's ``RESERVED_KEYS`` mapping, or ``{}`` when it declares
        none.

    Raises:
        ConfigError: If no such backend module exists.
    """
    keys = getattr(_load_backend(name), "RESERVED_KEYS", {})
    return dict(cast("Mapping[str, str]", keys))


def reserved_key_help() -> dict[str, str]:
    """Return every reserved profile key mapped to its help text.

    Covers :data:`BACKEND_KEY` itself plus each available backend's
    ``RESERVED_KEYS``. The config CLI uses this to prompt for and validate
    backend configuration without naming any backend. Empty under the
    ``"none"`` policy: no secret storage, so no key is legal.

    Returns:
        ``{key: help text}`` for every reserved profile key.
    """
    if schema_backend_policy() == _POLICY_NONE:
        return {}
    available = ", ".join(available_backends()) or "none"
    help_map = {
        BACKEND_KEY: f"Secret-storage backend for this profile (available: {available})",
    }
    for name in available_backends():
        help_map.update(backend_reserved_keys(name))
    return help_map


def reserved_profile_keys() -> frozenset[str]:
    """Return every config.toml key reserved for secret-backend machinery.

    The union of :data:`BACKEND_KEY` and each available backend's
    ``RESERVED_KEYS``. ``file.py`` treats these as legal profile keys during
    validation; when this module (or a backend file) is deleted, its keys
    disappear from the legal set and validation rejects them loudly.

    Returns:
        The reserved key names.
    """
    return frozenset(reserved_key_help())


def reserved_config(config: dict[str, Any], profile_values: dict[str, Any]) -> dict[str, Any]:
    """Return the merged reserved-key table for the active profile.

    Reserved keys (see :func:`reserved_profile_keys`) select and configure the
    secret backend; ``<field>_secret_name`` keys override storage names. Top-
    level values act as shared fallbacks; the profile table wins where both
    define a key.

    Args:
        config: Parsed TOML document.
        profile_values: The active profile's table (may be empty).

    Returns:
        The merged reserved-key mapping; empty under the ``"none"`` policy.
    """
    if schema_backend_policy() == _POLICY_NONE:
        return {}
    reserved = reserved_profile_keys()

    def keep(key: str) -> bool:
        return key in reserved or key.endswith(SECRET_NAME_SUFFIX)

    merged = {key: value for key, value in config.items() if keep(key)}
    merged.update({key: value for key, value in profile_values.items() if keep(key)})
    return merged


def backend_name(config: Mapping[str, Any]) -> str | None:
    """Return the backend selected by *config*, or the schema's default.

    Precedence: the profile's ``credential_backend`` key, then the schema's
    ``CREDENTIAL_BACKEND`` policy when it names a backend. ``"none"`` and
    ``"prompt"`` policies provide no default.

    Args:
        config: Merged reserved-key table for the active profile.

    Returns:
        The backend name, or None when neither the user nor the schema
        selects one.

    Raises:
        ConfigError: If ``credential_backend`` is present but not a non-empty
            string, or the schema policy is invalid.
    """
    name = config.get(BACKEND_KEY)
    if name is None:
        policy = schema_backend_policy()
        if policy in (_POLICY_NONE, _POLICY_PROMPT):
            return None
        return policy
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{BACKEND_KEY!r} must be a non-empty string, got {name!r}.")
    return name


def _load_backend(name: str) -> Any:
    """Import and return the ``<name>_backend`` module, by convention.

    Deliberately name-agnostic: any ``ip_info/config/<name>_backend.py``
    implementing the contract above is a valid backend.

    Args:
        name: Backend name from ``credential_backend``.

    Returns:
        The imported backend module.

    Raises:
        ConfigError: If the module does not exist -- the backend was removed,
            or the name is misspelled.
    """
    module_name = f"{_PACKAGE}.{name}{_BACKEND_SUFFIX}"
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise  # the backend exists but something it imports is missing
        available = ", ".join(available_backends()) or "none"
        raise ConfigError(
            f"{BACKEND_KEY}={name!r} but no such backend exists. Available backends: {available}."
        ) from exc


def require_backend(config: Mapping[str, Any], action: str) -> tuple[str, Any]:
    """Return the configured backend for a write-path *action*, loudly.

    Args:
        config: Merged reserved-key table for the active profile.
        action: Human description of the attempted operation, for the error.

    Returns:
        ``(name, module)`` of the configured backend.

    Raises:
        ConfigError: When no backend is configured, naming the available
            ones -- or, under the ``"none"`` policy, naming the policy.
    """
    name = backend_name(config)
    if name is None:
        if schema_backend_policy() == _POLICY_NONE:
            raise ConfigError(
                f"Cannot {action}: schema.CREDENTIAL_BACKEND is 'none', so this package "
                "stores no secrets. Provide secrets via environment variables instead."
            )
        available = ", ".join(available_backends()) or "none"
        raise ConfigError(
            f"Cannot {action}: no {BACKEND_KEY} is configured for this profile. "
            f"Choose one with '{CLI_NAME} set {BACKEND_KEY} <name>' "
            f"(available backends: {available})."
        )
    return name, _load_backend(name)


def get_secret(
    key: str, profile: str | None, config: Mapping[str, Any], *, optional: bool = False
) -> str | None:
    """Read secret *key* from the profile's backend.

    Args:
        key: Schema field name of the secret.
        profile: Active profile name, or None.
        config: Merged reserved-key table for the active profile.
        optional: The secret is optional (``secret(required=False)``): a
            missing storage name means it is not set, not a config error.

    Returns:
        The secret value, or None when not stored -- including when no
        backend is configured at all (the user may be supplying secrets via
        environment variables instead), and, for an optional secret, when
        config.toml gives it no storage name.

    Raises:
        ConfigError: If a configured backend is missing or unusable, or a
            required secret's storage name is not set in config.toml.
    """
    name = backend_name(config)
    if name is None:
        return None
    if optional and secret_name_key(key) not in config:
        return None
    backend = cast("_CredentialBackend", _load_backend(name))
    return backend.get(storage_name(key, config), service_name(profile), config)


def set_secret(key: str, value: str, profile: str | None, config: Mapping[str, Any]) -> None:
    """Store secret *key* in the profile's backend.

    Args:
        key: Schema field name of the secret.
        value: The secret value.
        profile: Active profile name, or None.
        config: Merged reserved-key table for the active profile.

    Raises:
        ConfigError: If no backend is configured, the backend is missing,
            unusable, or read-only, or the storage name is not set.
    """
    name, backend = require_backend(config, f"store secret {key!r}")
    setter = getattr(backend, "set", None)
    if setter is None:
        raise ConfigError(_read_only_message(name, backend))
    setter(storage_name(key, config), value, service_name(profile), config)


def delete_secret(key: str, profile: str | None, config: Mapping[str, Any]) -> None:
    """Delete secret *key* from the profile's backend.

    Args:
        key: Schema field name of the secret.
        profile: Active profile name, or None.
        config: Merged reserved-key table for the active profile.

    Raises:
        ConfigError: If no backend is configured, the backend is missing,
            unusable, or read-only, or the storage name is not set.
    """
    name, backend = require_backend(config, f"delete secret {key!r}")
    deleter = getattr(backend, "delete", None)
    if deleter is None:
        raise ConfigError(_read_only_message(name, backend))
    deleter(storage_name(key, config), service_name(profile), config)


def is_read_only(config: Mapping[str, Any]) -> bool:
    """Return True when the profile's backend cannot store secrets.

    Args:
        config: Merged reserved-key table for the active profile.

    Returns:
        True when a backend is selected (by profile or schema default) and it
        has no ``set``; False when it is writable or no backend is selected.

    Raises:
        ConfigError: If the selected backend module is missing.
    """
    name = backend_name(config)
    if name is None:
        return False
    return getattr(_load_backend(name), "set", None) is None


def read_only_notice(config: Mapping[str, Any]) -> str:
    """Return the read-only explanation for the profile's backend.

    Used by the config CLI to tell the user where the actual secret value
    lives when it skips the value prompt.

    Args:
        config: Merged reserved-key table for the active profile (must select
            a backend).

    Returns:
        The read-only message, including the backend's ``READ_ONLY_HINT``.

    Raises:
        ConfigError: If no backend is selected or the module is missing.
    """
    name = backend_name(config)
    if name is None:
        raise ConfigError("No credential backend is selected; nothing is read-only.")
    return _read_only_message(name, _load_backend(name))


def _read_only_message(name: str, backend: Any) -> str:
    """Build the error for write attempts against a read-only backend.

    Args:
        name: Backend name.
        backend: The backend module (may document its own update route in a
            ``READ_ONLY_HINT`` string).

    Returns:
        An actionable message naming how to update the secret instead.
    """
    hint = getattr(backend, "READ_ONLY_HINT", "update the secret at its source instead")
    return f"The {name!r} credential backend is read-only: {hint}."
