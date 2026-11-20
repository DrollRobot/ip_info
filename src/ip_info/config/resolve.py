"""Precedence engine that resolves settings values from every layer.

Precedence, highest wins:

1. Explicit overrides passed by calling code (e.g. from CLI flags).
2. Environment variables: ``<ENV_PREFIX><UPPER_FIELD_NAME>`` - the
   CI/headless path; works with zero files and zero secret storage.
3. Credential backend - secret fields only, and only when a backend is
   selected: the profile's ``credential_backend`` key, else the schema's
   ``CREDENTIAL_BACKEND`` default (never under the ``"none"``/``"prompt"``
   policies). Secrets are looked up under the profile's
   ``<field>_secret_name`` from config.toml, written by the config CLI; a
   missing name fails loudly for a required secret, and leaves an optional
   one unset.
4. config.toml: the selected profile table, then bare top-level keys.
5. Schema field defaults - non-secret fields only. Secret values never
   live in source; a schema giving a secret field a default value is
   rejected before resolution starts. An optional secret
   (``secret(required=False)``) that no layer provides is None.

The secret layer is optional: ``secrets.py`` is imported lazily and only
when the schema marks at least one field ``secret``, so a schema without
secret fields runs with the secret-storage machinery deleted entirely.

Profile selection, first match wins: the explicit ``profile`` argument, the
``<ENV_PREFIX>PROFILE`` environment variable, the ``default_profile`` key in
config.toml, else bare top-level keys act as the single unnamed profile.

``ENV_PREFIX`` is defined in ``schema.py`` as the app name upper-cased plus
an underscore; the two variables named above are :data:`PROFILE_ENV` here
and ``paths.CONFIG_DIR_ENV``.

Missing required values raise ``ConfigError`` with an actionable message; the
resolver never auto-creates config and never silently defaults.
"""

from __future__ import annotations

import importlib
import os
import types
import typing
from collections.abc import Iterable, Mapping
from dataclasses import fields
from pathlib import Path
from typing import Any, cast, get_args, get_origin, get_type_hints

from ip_info.config import file as config_file
from ip_info.config import paths
from ip_info.config.schema import (
    CLI_NAME,
    ENV_PREFIX,
    ConfigError,
    Settings,
    default_secret_name,
    is_optional_secret,
    is_required,
    is_secret,
)

# Environment variable selecting the active profile.
PROFILE_ENV = ENV_PREFIX + "PROFILE"


def load_settings(
    profile: str | None = None,
    overrides: Mapping[str, object] | None = None,
) -> Settings:
    """Resolve and return the effective :class:`Settings`.

    This is the public entry point application code should use::

        settings = load_settings(profile=args.profile)

    Args:
        profile: Profile name to resolve, or None to fall back to
            :data:`PROFILE_ENV` / ``default_profile`` / bare top-level keys.
        overrides: Highest-precedence values (e.g. parsed CLI flags), keyed by
            field name.

    Returns:
        A frozen ``Settings`` instance with every field populated.

    Raises:
        ConfigError: When a required value is missing from every layer, the
            config file is malformed, or a value has the wrong type.
    """
    return cast(
        "Settings",
        resolve_settings(Settings, profile=profile, overrides=overrides),
    )


def resolve_settings(
    schema: type[Any],
    *,
    profile: str | None = None,
    overrides: Mapping[str, object] | None = None,
    config_path: Path | None = None,
) -> Any:
    """Resolve an instance of *schema* through the full precedence chain.

    Generic engine behind :func:`load_settings`. Tests (and downstream repos
    with several settings groups) can run it against any frozen dataclass that
    follows the schema conventions documented in ``schema.py``.

    Args:
        schema: Frozen dataclass defining the options.
        profile: Explicit profile name, or None to auto-select.
        overrides: Highest-precedence values keyed by field name.
        config_path: Config file location; defaults to the standard path (see
            ``paths.py``).

    Returns:
        An instance of *schema* with every field populated.

    Raises:
        ConfigError: When a required value is missing from every layer, the
            config file is malformed, or a value has the wrong type.
    """
    instance, _, _ = _resolve(schema, profile, overrides, config_path)
    return instance


def resolve_with_sources(
    schema: type[Any],
    *,
    profile: str | None = None,
    overrides: Mapping[str, object] | None = None,
    config_path: Path | None = None,
) -> tuple[Any, dict[str, str], str | None]:
    """Resolve *schema* and report where each value came from.

    Used by the config CLI's ``show`` command so "which tenant am I about to
    hit, and why" is answerable in one step.

    Args:
        schema: Frozen dataclass defining the options.
        profile: Explicit profile name, or None to auto-select.
        overrides: Highest-precedence values keyed by field name.
        config_path: Config file location; defaults to the standard path.

    Returns:
        ``(instance, sources, profile_name)`` where ``sources`` maps each
        field name to a provenance label (``override``, ``env:<VAR>``, the
        backend name, ``file:profiles.<name>``, ``file:top-level``,
        ``default``, or ``not set`` for an optional secret no layer
        provides) and ``profile_name`` is the active profile, if any.

    Raises:
        ConfigError: As for :func:`resolve_settings`.
    """
    return _resolve(schema, profile, overrides, config_path)


def _resolve(
    schema: type[Any],
    profile: str | None,
    overrides: Mapping[str, object] | None,
    config_path: Path | None,
) -> tuple[Any, dict[str, str], str | None]:
    """Shared resolution engine returning the instance, sources, and profile.

    Args:
        schema: Frozen dataclass defining the options.
        profile: Explicit profile name, or None to auto-select.
        overrides: Highest-precedence values keyed by field name.
        config_path: Config file location, or None for the standard path.

    Returns:
        ``(instance, sources, profile_name)`` as documented on
        :func:`resolve_with_sources`.

    Raises:
        ConfigError: When a required value is missing from every layer, the
            config file is malformed, or a value has the wrong type.
    """
    _validate_schema_secrets(schema)
    path = config_path if config_path is not None else paths.config_path()
    overrides = overrides or {}

    document = config_file.read_config(path)
    config = document if document is not None else {}
    config_file.validate_config(config, schema, path)

    profile_name = select_profile_name(profile, config, path)
    profile_values = config_file.profile_table(config, profile_name, path)

    hints = get_type_hints(schema)
    secret_names = {f.name for f in fields(schema) if is_secret(f)}
    secrets_module: Any = _secrets_module(secret_names) if secret_names else None
    backend_config: dict[str, Any] = (
        secrets_module.reserved_config(config, profile_values) if secrets_module else {}
    )
    values: dict[str, Any] = {}
    sources: dict[str, str] = {}
    missing: list[str] = []
    for f in fields(schema):
        optional_secret = is_optional_secret(f)
        # An optional secret is annotated 'str | None' (checked above): any
        # value a layer provides is a str, and None only means "not set".
        tp = str if optional_secret else hints[f.name]
        if f.name in overrides:
            values[f.name] = _check_type(f.name, overrides[f.name], tp, "overrides")
            sources[f.name] = "override"
            continue
        env_name = ENV_PREFIX + f.name.upper()
        env_raw = os.environ.get(env_name)
        if env_raw is not None:
            values[f.name] = coerce_string(env_name, env_raw, tp)
            sources[f.name] = f"env:{env_name}"
            continue
        if is_secret(f):
            secret = secrets_module.get_secret(
                f.name, profile_name, backend_config, optional=optional_secret
            )
            if secret is not None:
                values[f.name] = secret
                sources[f.name] = secrets_module.backend_name(backend_config)
                continue
        else:
            if f.name in profile_values:
                where = f"profile 'profiles.{profile_name}' in {path}"
                values[f.name] = _check_type(f.name, profile_values[f.name], tp, where)
                sources[f.name] = f"file:profiles.{profile_name}"
                continue
            if f.name in config:
                where = f"the top level of {path}"
                values[f.name] = _check_type(f.name, config[f.name], tp, where)
                sources[f.name] = "file:top-level"
                continue
        if is_required(f):
            missing.append(f.name)
        elif optional_secret:
            sources[f.name] = "not set"
        else:
            sources[f.name] = "default"

    if missing:
        missing_secrets = [name for name in missing if name in secret_names]
        backend_hint = None
        if missing_secrets and secrets_module.schema_backend_policy() == "none":
            backend_hint = (
                "schema.CREDENTIAL_BACKEND is 'none': secrets come from environment variables only."
            )
            missing_secrets = []  # there is no set-secret command to point at
        elif missing_secrets and secrets_module.backend_name(backend_config) is None:
            available = ", ".join(secrets_module.available_backends()) or "none"
            backend_hint = (
                f"No credential_backend is configured; choose one with "
                f"'{CLI_NAME} set credential_backend <name>' (available: {available})."
            )
        if profile_name is None and config.get("profiles"):
            raise ConfigError(_no_profile_message(path, sorted(config["profiles"])))
        raise ConfigError(
            _missing_message(
                missing, missing_secrets, document is not None, path, profile_name, backend_hint
            )
        )
    return schema(**values), sources, profile_name


def _validate_schema_secrets(schema: type[Any]) -> None:
    """Reject schemas that mishandle secret fields, before any resolution.

    A default on a secret field is a secret value in source, silently used
    whenever the backend lookup misses. ``schema.secret(...)`` cannot
    express one; this guard catches hand-written ``field(...)``
    declarations that can. The one exception is an optional secret's None,
    which means "not set": it must be exactly None, on a field annotated
    ``str | None``.

    Args:
        schema: Frozen dataclass defining the options.

    Raises:
        ConfigError: When a secret field has a default value or leaves
            ``repr`` enabled, an optional secret's default is not None or
            its annotation is not ``str | None``, or a non-secret field
            declares a ``default_secret_name``.
    """
    hints = get_type_hints(schema)
    for f in fields(schema):
        if not is_secret(f):
            if default_secret_name(f) is not None:
                raise ConfigError(
                    f"Field {f.name!r} declares default_secret_name but is not secret. "
                    "Storage names apply only to secret fields."
                )
            continue
        if is_optional_secret(f):
            # The default's value is never echoed: it may be a real secret.
            if f.default is not None:
                raise ConfigError(
                    f"Optional secret field {f.name!r} must have the default None and no "
                    "other: any other default is a secret value in source. Declare it with "
                    "schema.secret(..., required=False)."
                )
            if not _is_optional_str(hints[f.name]):
                raise ConfigError(
                    f"Optional secret field {f.name!r} must be annotated 'str | None': it is "
                    "None when no layer provides it."
                )
        elif not is_required(f):
            raise ConfigError(
                f"Secret field {f.name!r} has a default value: a secret value in source. "
                "Secrets never live in source. Remove the default; declare the field with "
                f"schema.secret(...) and store the value with '{CLI_NAME} set-secret "
                f"{f.name}'."
            )
        if f.repr:
            raise ConfigError(
                f"Secret field {f.name!r} must set repr=False so its value cannot leak "
                "through repr()/tracebacks. Declare it with schema.secret(...)."
            )


def _is_optional_str(tp: Any) -> bool:
    """Return True if the type annotation *tp* is ``str | None``.

    Accepts both spellings, ``str | None`` and ``Optional[str]``, which older
    Python versions build as two distinct union types.

    Args:
        tp: A resolved type annotation.

    Returns:
        True when *tp* is a union of exactly ``str`` and ``None``.
    """
    return get_origin(tp) in (types.UnionType, typing.Union) and set(get_args(tp)) == {
        str,
        type(None),
    }


def _secrets_module(secret_fields: Iterable[str]) -> Any:
    """Import and return the secret-machinery module (``secrets.py``), lazily.

    Called only when the schema marks at least one field ``secret``, so a
    schema without secret fields never touches -- and can be shipped
    without -- the secret-storage machinery.

    Args:
        secret_fields: The schema's secret field names, for the error message.

    Returns:
        The imported ``secrets`` module.

    Raises:
        ConfigError: When ``secrets.py`` has been removed from the package
            while the schema still declares secret fields.
    """
    module_name = f"{__package__}.secrets"
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise
        raise ConfigError(
            f"The settings schema marks {', '.join(sorted(secret_fields))} as secret, but "
            "the secret-storage machinery (secrets.py) has been removed from this package. "
            "Restore it (plus at least one *_backend.py module), or remove the "
            '"secret": True fields from the schema.'
        ) from exc


def select_profile_name(
    explicit: str | None,
    config: dict[str, Any],
    path: Path,
) -> str | None:
    """Pick the active profile name, or None for bare top-level mode.

    Selection order: *explicit* argument, then the :data:`PROFILE_ENV`
    environment variable, then ``default_profile`` in the config file.

    Args:
        explicit: Profile name passed by the caller, if any.
        config: Parsed config document (may be empty).
        path: Config file path, for error messages.

    Returns:
        The selected profile name, or None when no profile applies.

    Raises:
        ConfigError: If a profile was requested but the config file is absent
            or does not define it (raised by ``profile_table`` later for the
            not-defined case; here for the no-file case).
    """
    name = explicit or os.environ.get(PROFILE_ENV) or config.get("default_profile")
    if name is not None and not config:
        raise ConfigError(
            f"Profile {name!r} requested but no config file exists at {path}. "
            f"Run '{CLI_NAME} init --profile {name}' to create it."
        )
    return cast("str | None", name)


def coerce_string(name: str, raw: str, tp: Any) -> Any:
    """Convert the string *raw* to the field type *tp*.

    Environment variables and CLI arguments are the only untyped layers (TOML
    values arrive typed; overrides come from typed code), so this is the only
    place string conversion happens. Supported types: ``str``, ``int``,
    ``float``, ``bool`` (``true``/``false``, case-insensitive), and
    ``list[str]`` (comma-separated).

    Args:
        name: Where the string came from (env-var name or CLI argument), for
            error messages.
        raw: The raw string value.
        tp: The field's resolved type annotation.

    Returns:
        The converted value.

    Raises:
        ConfigError: When the string cannot be converted to *tp*, or *tp* is
            not supported for string input.
    """
    if tp is str:
        return raw
    if tp is bool:
        lowered = raw.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
        raise ConfigError(f"{name} must be 'true' or 'false', got {raw!r}.")
    if tp is int:
        try:
            return int(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be an integer, got {raw!r}.") from exc
    if tp is float:
        try:
            return float(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be a number, got {raw!r}.") from exc
    if get_origin(tp) is list and get_args(tp) == (str,):
        return [item.strip() for item in raw.split(",") if item.strip()]
    raise ConfigError(f"{name}: type {tp!r} does not support string input.")


def _check_type(name: str, value: Any, tp: Any, where: str) -> Any:
    """Verify that *value* matches the field type *tp*; fail loudly otherwise.

    ``bool`` is checked before ``int`` because ``bool`` subclasses ``int`` in
    Python. An ``int`` is accepted for a ``float`` field (TOML users write
    ``1`` for ``1.0``) and converted.

    Args:
        name: Field name, for error messages.
        value: The value found in the layer.
        tp: The field's resolved type annotation.
        where: Human description of the layer, for error messages.

    Returns:
        The value, converted to ``float`` when an int fills a float field.

    Raises:
        ConfigError: When the value's type does not match *tp*.
    """
    ok: bool
    if tp is bool:
        ok = isinstance(value, bool)
    elif tp is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif tp is float:
        ok = isinstance(value, int | float) and not isinstance(value, bool)
        if ok:
            value = float(value)
    elif tp is str:
        ok = isinstance(value, str)
    elif get_origin(tp) is list and get_args(tp) == (str,):
        ok = isinstance(value, list) and all(isinstance(item, str) for item in value)
    else:
        raise ConfigError(f"Field {name!r} has unsupported type {tp!r}.")
    if not ok:
        raise ConfigError(
            f"{name!r} in {where} must be {tp!r}, got {type(value).__name__} ({value!r})."
        )
    return value


def _no_profile_message(path: Path, profile_names: list[str]) -> str:
    """Build the error message for a file with profiles when none is selected.

    Reporting missing values misleads here: the values usually sit in a
    profile, and the real fault is that no profile was picked.

    Args:
        path: Config file path.
        profile_names: The profiles the file defines, sorted.

    Returns:
        A single-string message listing the profiles and every way to select one.
    """
    return (
        f"No profile selected. Profiles defined in {path}: {', '.join(profile_names)}. "
        "Select one with --profile NAME or "
        f"the {PROFILE_ENV} environment variable, or set a default with "
        f"'{CLI_NAME} use NAME'."
    )


def _missing_message(
    missing: list[str],
    missing_secrets: list[str],
    file_exists: bool,
    path: Path,
    profile_name: str | None,
    backend_hint: str | None,
) -> str:
    """Build the actionable error message for missing required values.

    Args:
        missing: Field names that no layer provided.
        missing_secrets: The subset of *missing* that are secret fields.
        file_exists: Whether the config file was found at all.
        path: Config file path.
        profile_name: The active profile, or None for bare top-level mode.
        backend_hint: Extra sentence naming how to configure a credential
            backend, when secrets are missing and none is configured.

    Returns:
        A single-string message naming every missing field, its env var, and
        the CLI command that provides it.
    """
    env_vars = ", ".join(ENV_PREFIX + name.upper() for name in missing)
    if file_exists:
        source = f"config file {path} (profile: {profile_name or 'none - top-level keys'})"
    else:
        source = f"no config file found at {path}"
    message = (
        f"Missing required configuration value(s): {', '.join(missing)}. "
        f"Searched overrides, environment ({env_vars}), credential backend (secret fields), "
        f"and {source}. "
        f"Run '{CLI_NAME} init' to create the config interactively, or set the "
        "environment variable(s) above."
    )
    if backend_hint:
        message += f" {backend_hint}"
    if missing_secrets:
        stores = " ".join(f"'{CLI_NAME} set-secret {name}'" for name in missing_secrets)
        message += f" Store missing secret(s) with: {stores}."
    return message
