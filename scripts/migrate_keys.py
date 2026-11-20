"""Move provider API keys from the ip_info 1.x keyring layout to the 2.0 config system.

ip_info 1.x kept each provider's API key in the OS keyring under the service
``ip_info-<provider>`` and the user ``default``. 2.0 keeps them as optional
secrets of the config system: the keyring service ``ip_info``, each under the
storage name that config.toml gives it.

Run it once, from a checkout of this repo, as the user whose keys they are:

    uv run scripts/migrate_keys.py

For each provider key it finds in the 1.x layout, it:

1. names the key in config.toml (``<provider>_api_key_secret_name``), unless
   config.toml already names it;
2. stores the key in the new layout, unless the same value is already there;
3. reads it back to check it;
4. deletes the 1.x entry, so no stale copy of the secret is left behind.

A key already stored in the new layout with a different value is left alone
in both places and reported: the user decides which one is right.

It migrates into the top level of config.toml (the unnamed profile), and
stops if config.toml selects a ``default_profile``.
"""

from __future__ import annotations

import sys
from typing import Any

import keyring

from ip_info.config import ConfigError, paths, secrets
from ip_info.config import cli as config_cli
from ip_info.config import file as config_file
from ip_info.constants import API_METADATA

# Where ip_info 1.x stored each key: service "ip_info-<provider>", user "default".
OLD_SERVICE_PREFIX = "ip_info-"
OLD_USERNAME = "default"

# Outcomes of migrating one provider's key.
MOVED = "moved"
ALREADY_THERE = "already in the new layout; 1.x copy removed"
CONFLICT = "CONFLICT"
NOT_FOUND = "no 1.x key"


def _read_config() -> dict[str, Any]:
    """Return the parsed config.toml, or an empty table when there is none.

    Returns:
        The parsed document.

    Raises:
        ConfigError: If the file is malformed, or it selects a
            ``default_profile`` (this script migrates the top level only).
    """
    path = paths.config_path()
    config = config_file.read_config(path) or {}
    if "default_profile" in config:
        raise ConfigError(
            f"{path} selects default_profile {config['default_profile']!r}. "
            "migrate_keys.py moves keys into the top level of config.toml only. "
            "Remove default_profile, run it, then set default_profile again."
        )
    return config


def _backend_config() -> dict[str, Any]:
    """Return the top-level reserved-key table: backend choice and storage names.

    Returns:
        The merged reserved-key mapping for the unnamed profile.
    """
    return dict(secrets.reserved_config(_read_config(), {}))


def _name_key_in_config(field: str) -> None:
    """Name secret *field* in config.toml, unless config.toml already names it.

    Writes through the config command, as ``ip-info-config set`` would.

    Args:
        field: The secret's schema field name.

    Raises:
        ConfigError: If the config command fails.
    """
    name_key = secrets.secret_name_key(field)
    if name_key in _read_config():
        return
    if config_cli.main(["set", name_key, field]) != 0:
        raise ConfigError(f"Could not set {name_key} in {paths.config_path()}.")


def migrate_key(api_name: str) -> str:
    """Move one provider's API key from the 1.x keyring layout to the new one.

    Args:
        api_name: Provider name, a key of ``constants.API_METADATA``.

    Returns:
        One of :data:`MOVED`, :data:`ALREADY_THERE`, :data:`CONFLICT` or
        :data:`NOT_FOUND`.

    Raises:
        ConfigError: If the keyring or config.toml cannot be used, or the key
            does not read back as stored.
    """
    old_service = OLD_SERVICE_PREFIX + api_name
    value = keyring.get_password(old_service, OLD_USERNAME)
    if not value:
        return NOT_FOUND

    field = f"{api_name}_api_key"
    _name_key_in_config(field)
    backend_config = _backend_config()
    existing = secrets.get_secret(field, None, backend_config, optional=True)
    if existing is not None and existing != value:
        return CONFLICT
    if existing is None:
        secrets.set_secret(field, value, None, backend_config)
        if secrets.get_secret(field, None, backend_config, optional=True) != value:
            raise ConfigError(
                f"{field} did not read back as stored; the 1.x copy was left in place."
            )
    keyring.delete_password(old_service, OLD_USERNAME)
    return ALREADY_THERE if existing is not None else MOVED


def main(argv: list[str] | None = None) -> int:
    """Migrate every provider's key and report each one found.

    Args:
        argv: Arguments after the program name (none are accepted); ``None``
            for ``sys.argv[1:]``.

    Returns:
        0 when every key moved or none needed moving; 1 on a conflict or an
        error; 2 on a usage error.
    """
    args = sys.argv[1:] if argv is None else argv
    if args:
        print(f"usage: migrate_keys.py  (takes no arguments, got {args})", file=sys.stderr)
        return 2
    conflicts: list[str] = []
    found = 0
    try:
        for api_name in API_METADATA:
            outcome = migrate_key(api_name)
            if outcome == NOT_FOUND:
                continue
            found += 1
            print(f"{api_name}: {outcome}")
            if outcome == CONFLICT:
                conflicts.append(api_name)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if not found:
        print("No 1.x keys found; nothing to migrate.")
    for api_name in conflicts:
        print(
            f"{api_name}: a different key is already stored in the new layout. Check it with "
            f"'ip-info-config show', replace it with 'ip-info-config set-secret "
            f"{api_name}_api_key' if needed, then delete the 1.x copy: keyring service "
            f"{OLD_SERVICE_PREFIX + api_name!r}, user {OLD_USERNAME!r}.",
            file=sys.stderr,
        )
    return 1 if conflicts else 0


if __name__ == "__main__":
    sys.exit(main())
