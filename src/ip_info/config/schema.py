"""Single source of truth for this package's configuration options.

The :class:`Settings` dataclass below is THE one place where configuration
option names, types, defaults, secret classification, and help text are
defined. Everything else derives from it by iterating
``dataclasses.fields(Settings)``:

- ``resolve.py`` resolves each field through the precedence layers.
- ``file.py`` validates config.toml keys against the field names.
- The config CLI prompts and validates per field.
- Tests build fake configurations from the same field list.

To add, rename, or remove an option: edit :class:`Settings`; nothing else
needs changing.

Field conventions -- declare every field with :func:`option` or
:func:`secret`, never with a bare ``field(default=...)``:

- ``option(...)``: a non-secret. ``default_value`` is the value used when
  no layer provides one; omit it to make the option required.
- ``secret(...)``: a secret. Secret values never appear in source, so
  secret fields cannot have default values, and are required unless
  declared ``required=False``. An optional secret is annotated
  ``str | None`` and is ``None`` when no layer provides it, for example
  ``webhook_token: str | None = secret(help="...", required=False)``.
  ``default_secret_name`` is the backend storage NAME the config CLI
  offers at init and writes to config.toml as ``<field>_secret_name``;
  runtime reads the name from config.toml only.
- Both take ``help``: the description used in prompts and comments.
- All fields are keyword-only, so declaration order is free.
- A schema with no secret fields never touches the secret machinery, which
  can then be removed from the package entirely.
"""

from __future__ import annotations

from dataclasses import MISSING, Field, dataclass, field
from pathlib import Path
from typing import Any

import platformdirs

# The application name, used for the config directory, env-var prefix, CLI
# name, and keyring service name. Kept as a literal (not derived from
# __package__) so a project-wide find-replace of the package name updates it.
APP_NAME = "ip_info"

# Prefix for every environment-variable override: the app name upper-cased,
# so the field 'tenant_id' is overridden by <ENV_PREFIX>TENANT_ID.
ENV_PREFIX = APP_NAME.upper() + "_"

# Name of the config CLI's console script, used in error messages.
CLI_NAME = APP_NAME.replace("_", "-") + "-config"

# Credential-backend policy for every secret field in the schema. One of:
#
# - "none":    this package stores no secrets. Secret fields resolve from
#              environment variables only; the config CLI grows no secret
#              commands and the reserved backend keys become illegal in
#              config.toml.
# - a backend name (e.g. "keyring", "keyvault"): the default backend. Used
#              without prompting; a user may still override it per profile
#              with 'credential_backend' in config.toml (via the config CLI).
# - "prompt":  no default. The config CLI's init asks the user to choose.
#
# Validated at use time by secrets.schema_backend_policy(); an unknown value
# fails loudly there. ip_info keeps provider API keys in the OS keyring.
CREDENTIAL_BACKEND = "keyring"


class ConfigError(Exception):
    """Raised for any configuration problem: missing, malformed, or mistyped values."""


def option(
    *,
    help: str,
    default_value: Any = MISSING,
    default_factory: Any = MISSING,
) -> Any:
    """Declare a non-secret settings field.

    Args:
        help: Description used in prompts and generated comments.
        default_value: Value used when no layer provides one. Omit to make
            the option required.
        default_factory: Zero-argument callable producing the default, for
            mutable defaults. Mutually exclusive with ``default_value``.

    Returns:
        A dataclass field for the settings schema.

    Raises:
        ValueError: If both defaults are given.
    """
    if default_value is not MISSING and default_factory is not MISSING:
        raise ValueError("Pass default_value or default_factory, not both.")
    kwargs: dict[str, Any] = {"kw_only": True, "metadata": {"help": help}}
    if default_value is not MISSING:
        kwargs["default"] = default_value
    if default_factory is not MISSING:
        kwargs["default_factory"] = default_factory
    return field(**kwargs)


def secret(
    *,
    help: str,
    default_secret_name: str | None = None,
    required: bool = True,
) -> Any:
    """Declare a secret settings field.

    Secret values never appear in source: the field cannot take a default
    value. Values come from the credential backend, or an environment
    variable at runtime. A required secret missing from every layer is a
    configuration error; an optional one (``required=False``) is ``None``.

    Args:
        help: Description used in prompts and generated comments.
        default_secret_name: Backend storage NAME (a name, not a value) the
            config CLI offers at init and writes to config.toml as
            ``<field>_secret_name``. Omit to offer the field name.
        required: False declares an optional secret. Annotate the field
            ``str | None``. Its default, None, means "not set"; it is not a
            value in source.

    Returns:
        A dataclass field for the settings schema (``repr=False`` so the
        value cannot leak through ``repr()``/tracebacks).

    Raises:
        ValueError: If ``default_secret_name`` is empty.
    """
    metadata: dict[str, Any] = {"secret": True, "help": help}
    if default_secret_name is not None:
        if not isinstance(default_secret_name, str) or not default_secret_name:
            raise ValueError(
                f"default_secret_name must be a non-empty string, got {default_secret_name!r}."
            )
        metadata["default_secret_name"] = default_secret_name
    if not required:
        metadata["optional"] = True
        return field(default=None, repr=False, kw_only=True, metadata=metadata)
    return field(repr=False, kw_only=True, metadata=metadata)


def default_db_path() -> str:
    """Return the default location of the lookup cache database.

    The OS-standard per-user data folder, not the package folder: a reinstall
    replaces the package folder, and it may not be writable.

    Returns:
        ``<user data dir>/ip_info.db``; on Windows the data dir is
        ``%LOCALAPPDATA%/ip_info``.
    """
    data_dir = platformdirs.user_data_dir(APP_NAME, appauthor=False, roaming=False)
    return str(Path(data_dir) / "ip_info.db")


# Help text for the providers that work without a key (requires_key False in
# constants.API_METADATA), and for those skipped without one.
_KEY_OPTIONAL = "optional; the provider also works without one"
_KEY_NEEDED = "the provider is skipped without one"


@dataclass(frozen=True)
class Settings:
    """Resolved configuration for one profile.

    Instances are produced by :func:`ip_info.config.load_settings`
    after applying the full precedence chain (explicit overrides > env vars >
    secret backend > config.toml > field defaults). Application code should
    treat instances as immutable value objects.

    Each provider in ``constants.API_METADATA`` has one optional secret,
    ``<provider>_api_key``, read by name in ``main.py``.
    """

    db_path: str = option(
        help="SQLite file that caches lookups and rate-limit counters",
        default_factory=default_db_path,
    )
    abstractapicom_api_key: str | None = secret(
        help=f"AbstractAPI.com API key; {_KEY_NEEDED}", required=False
    )
    abuseipdbcom_api_key: str | None = secret(
        help=f"AbuseIPDB.com API key; {_KEY_NEEDED}", required=False
    )
    criminalipio_api_key: str | None = secret(
        help=f"CriminalIP.io API key; {_KEY_NEEDED}", required=False
    )
    ip2locationio_api_key: str | None = secret(
        help=f"IP2Location.io API key; {_KEY_OPTIONAL}", required=False
    )
    ipapico_api_key: str | None = secret(help=f"IPAPI.co API key; {_KEY_OPTIONAL}", required=False)
    ipapicom_api_key: str | None = secret(help=f"IPAPI.com API key; {_KEY_NEEDED}", required=False)
    ipapiis_api_key: str | None = secret(help=f"IPAPI.is API key; {_KEY_NEEDED}", required=False)
    ipapiorg_api_key: str | None = secret(help=f"IPAPI.org API key; {_KEY_NEEDED}", required=False)
    ipdashapicom_api_key: str | None = secret(
        help=f"IP-API.com API key; {_KEY_OPTIONAL}", required=False
    )
    ipgeolocationio_api_key: str | None = secret(
        help=f"IPGeolocation.io API key; {_KEY_NEEDED}", required=False
    )
    ipinfoio_api_key: str | None = secret(help=f"IPInfo.io API key; {_KEY_NEEDED}", required=False)
    ipqueryio_api_key: str | None = secret(
        help=f"IPQuery.io API key; {_KEY_OPTIONAL}", required=False
    )
    ipregistryco_api_key: str | None = secret(
        help=f"IPRegistry.co API key; {_KEY_NEEDED}", required=False
    )
    virustotalcom_api_key: str | None = secret(
        help=f"VirusTotal.com API key; {_KEY_NEEDED}", required=False
    )


def is_secret(f: Field[Any]) -> bool:
    """Return True if *f* is marked as a secret in its metadata.

    Args:
        f: A dataclass field of the settings schema.

    Returns:
        True when the field's value must come from a secret backend and never
        from config.toml.
    """
    return bool(f.metadata.get("secret", False))


def is_optional_secret(f: Field[Any]) -> bool:
    """Return True if *f* is a secret declared with ``secret(required=False)``.

    Args:
        f: A dataclass field of the settings schema.

    Returns:
        True when the field is a secret that resolves to None, rather than
        failing, when no layer provides it.
    """
    return is_secret(f) and bool(f.metadata.get("optional", False))


def field_help(f: Field[Any]) -> str:
    """Return the human-readable description of *f* (empty string if unset).

    Args:
        f: A dataclass field of the settings schema.

    Returns:
        The ``help`` metadata string, or ``""`` when none was provided.
    """
    return str(f.metadata.get("help", ""))


def is_required(f: Field[Any]) -> bool:
    """Return True if *f* has no default and must be provided by some layer.

    Args:
        f: A dataclass field of the settings schema.

    Returns:
        True when the field has neither a default value nor a default factory.
    """
    return f.default is MISSING and f.default_factory is MISSING


def default_secret_name(f: Field[Any]) -> str | None:
    """Return *f*'s schema-declared backend storage name, if any.

    Args:
        f: A dataclass field of the settings schema.

    Returns:
        The ``default_secret_name`` metadata string, or None (the config
        CLI then offers the field name).
    """
    name = f.metadata.get("default_secret_name")
    return str(name) if name is not None else None


def field_default(f: Field[Any]) -> Any:
    """Return the field's default, materializing a default factory if needed.

    Args:
        f: A dataclass field of the settings schema (must not be required).

    Returns:
        The default value.

    Raises:
        ValueError: If the field is required and therefore has no default.
    """
    if f.default is not MISSING:
        return f.default
    if f.default_factory is not MISSING:
        return f.default_factory()
    raise ValueError(f"Field {f.name!r} is required and has no default.")
