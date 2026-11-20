"""OS-keyring credential backend.

Stores secrets in the OS-native credential store: Windows Credential Manager,
macOS Keychain, or Linux Secret Service (GNOME Keyring / KWallet). Selected
by ``credential_backend = "keyring"`` in a profile. Secrets are namespaced
per profile via the keyring *service* (``ip_info:<profile>``);
the *username* slot holds the secret's storage name.

The ``keyring`` package is an optional dependency (the ``keyring`` extra) and
is imported lazily, so this module is importable - and the rest of the config
system fully usable - without it installed.

The *username* slot holds the secret's storage name: the schema field name by
default, or the profile's ``<field>_secret_name`` override (resolved by the
dispatcher before this module is called).

Headless hosts (Linux without D-Bus/SecretService, containers, CI) have no
usable keyring; ``keyring`` then selects a fail/null backend. That is
detected on first use and raised as an actionable error naming the
alternatives -- this backend never falls back to writing plaintext anywhere.

To remove the keyring backend entirely: delete this file and its test module
``tests/test_keyring_backend.py``, and delete the ``keyring`` extra in
``pyproject.toml``'s ``[project.optional-dependencies]`` (then run
``uv lock`` and ``uv sync --all-extras``). With this file gone there are no
``keyring`` imports anywhere, and profiles must select another backend.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import ModuleType
from typing import Any, cast

from ip_info.config.schema import CLI_NAME, ConfigError

# Backend-specific config.toml keys this backend consumes, mapped to the help
# text shown when prompting for them. The dispatcher (secrets.py) unions these
# into the set of reserved profile keys; the keyring backend needs none.
RESERVED_KEYS: dict[str, str] = {}


def _import_keyring() -> ModuleType:
    """Import and return the ``keyring`` package, failing loudly when absent.

    Returns:
        The imported ``keyring`` module (with the submodules used here loaded).

    Raises:
        ConfigError: When the ``keyring`` package is not installed.
    """
    try:
        import keyring
        import keyring.backends.chainer
        import keyring.backends.fail
        import keyring.errors
    except ModuleNotFoundError as exc:
        raise ConfigError(
            "The keyring credential backend needs the 'keyring' package, which is an "
            "optional dependency. Install it with the 'keyring' extra (e.g. "
            "'uv sync --extra keyring', or 'pip install <package>[keyring]'), or select "
            "another credential_backend."
        ) from exc
    return keyring


def _require_usable_backend(keyring: ModuleType) -> None:
    """Raise when the active keyring backend cannot actually store secrets.

    Args:
        keyring: The imported ``keyring`` module.

    Raises:
        ConfigError: On fail/null backends (headless Linux, containers), with
            the alternatives named.
    """
    active = keyring.get_keyring()
    unusable = isinstance(active, keyring.backends.fail.Keyring) or (
        isinstance(active, keyring.backends.chainer.ChainerBackend) and not active.backends
    )
    if unusable:
        raise ConfigError(
            "No usable OS keyring backend is available on this host (common on headless "
            "Linux and containers). Provide secrets via environment variables instead, or "
            "select another credential_backend. Secrets are never written to disk as a "
            "fallback."
        )


def get(key: str, service: str, config: Mapping[str, Any]) -> str | None:
    """Read secret *key* from the OS keyring.

    Args:
        key: Schema field name of the secret.
        service: Profile-scoped keyring service name.
        config: Merged reserved-key table (unused by this backend).

    Returns:
        The stored value, or None when not present.

    Raises:
        ConfigError: When the keyring package is missing or no usable keyring
            backend exists.
    """
    keyring = _import_keyring()
    _require_usable_backend(keyring)
    return cast("str | None", keyring.get_password(service, key))


def set(key: str, value: str, service: str, config: Mapping[str, Any]) -> None:
    """Store secret *key* in the OS keyring.

    Args:
        key: Schema field name of the secret.
        value: The secret value.
        service: Profile-scoped keyring service name.
        config: Merged reserved-key table (unused by this backend).

    Raises:
        ConfigError: When the keyring package is missing or no usable keyring
            backend exists.
    """
    keyring = _import_keyring()
    _require_usable_backend(keyring)
    keyring.set_password(service, key, value)


def delete(key: str, service: str, config: Mapping[str, Any]) -> None:
    """Delete secret *key* from the OS keyring.

    Args:
        key: Schema field name of the secret.
        service: Profile-scoped keyring service name.
        config: Merged reserved-key table (unused by this backend).

    Raises:
        ConfigError: When the keyring package is missing, no usable keyring
            backend exists, or the key is not stored (so a typo'd delete fails
            loudly instead of silently).
    """
    keyring = _import_keyring()
    _require_usable_backend(keyring)
    try:
        keyring.delete_password(service, key)
    except keyring.errors.PasswordDeleteError as exc:
        raise ConfigError(
            f"No secret named {key!r} is stored for service {service!r}; nothing deleted. "
            f"Run '{CLI_NAME} show' to see which secrets are set."
        ) from exc
