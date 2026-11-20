"""The config CLI: create, inspect, and edit config.toml and stored secrets.

One command group covers everything -- non-secret values and secrets alike --
so no hand-editing of config.toml is ever required:

===================  ========================================================
Command              Behavior
===================  ========================================================
``init``             Interactive first-time setup; prompts from the schema;
                     non-secrets go to config.toml; when the schema has
                     secret fields, selects a credential backend (the
                     schema's ``CREDENTIAL_BACKEND`` default, or a prompt
                     under the ``"prompt"`` policy), collects each secret's
                     backend storage NAME (visible input), then stores
                     secret VALUES via hidden prompts -- writable backends
                     only; read-only backends get the storage names plus a
                     pointer at where the values live. Each optional secret
                     is asked about first and skipped entirely on "no".
                     ``--force`` starts
                     over: the new file replaces the whole existing one
                     (every profile, every comment); secret values already
                     in the backend stay there.
``path``             Print the resolved config file path.
``open``             Open config.toml in the program the OS associates
                     with the file type.
``show``             Effective config after full resolution, secrets masked
                     (an unset optional secret shows as None), with each
                     value's provenance.
``set KEY VALUE``    Write a non-secret to config.toml (comment-preserving).
                     Also accepts the reserved backend keys
                     (``credential_backend`` and whatever each backend
                     declares), so the user picks where secrets live.
``unset KEY``        Remove a key so the schema default applies again.
``list-profiles``    Profile names, marking the default.
``use PROFILE``      Set ``default_profile``.
``set-secret KEY``   Prompt for the storage NAME (visible; persisted to
                     config.toml) and the VALUE (hidden), then store in the
                     profile's backend. On a read-only backend: name only,
                     never a value prompt.
``delete-secret KEY``  Remove a secret from the profile's backend.
===================  ========================================================

The two secret commands exist only when the schema marks at least one field
``secret`` and its ``CREDENTIAL_BACKEND`` policy is not ``"none"``. The
secret-storage machinery (``secrets.py``) is imported lazily and only on
paths that need it, so with no secret fields in the schema this CLI runs
with that machinery deleted from the package.

Exposed as the ``ip-info-config`` console script and as
``python -m ip_info.config``. Writes go through ``tomlkit`` so
user comments in config.toml survive edits; secret values never touch the
file and are never accepted as command-line arguments (shell history).
"""

from __future__ import annotations

import argparse
import getpass
import importlib
import os
import shutil
import subprocess
import sys
from dataclasses import Field, fields
from pathlib import Path
from typing import Any, get_type_hints

import tomlkit
import tomlkit.exceptions

from ip_info.config import paths
from ip_info.config import schema as schema_module
from ip_info.config.resolve import (
    coerce_string,
    resolve_with_sources,
    select_profile_name,
)
from ip_info.config.schema import (
    CLI_NAME,
    ConfigError,
    Settings,
    default_secret_name,
    field_default,
    field_help,
    is_optional_secret,
    is_required,
    is_secret,
)

_SECRET_MASK = "********"  # noqa: S105  (display placeholder, not a credential)

# Answers accepted by _confirm, mapped to the choice they make.
_YES_NO = {"y": True, "yes": True, "n": False, "no": False}


def _has_secret_fields() -> bool:
    """Return True when the schema declares at least one secret field.

    Gates every secret-storage path: with no secret fields, secrets.py is
    never imported and the secret commands are not registered. Read at call
    time, never snapshotted at import, so it tracks the schema actually in
    force (tests swap ``Settings``; a downstream project replaces it).

    Returns:
        True when any field of ``Settings`` is marked secret.
    """
    return any(is_secret(f) for f in fields(Settings))


def _secret_storage_active() -> bool:
    """Return True when secret storage is in play at all.

    Secret fields exist AND the schema's CREDENTIAL_BACKEND policy is not
    ``"none"``. The raw constant is read here (missing means ``"prompt"``,
    the pre-policy behavior); full validation happens in
    ``secrets.schema_backend_policy()`` on the paths that use it. Like
    :func:`_has_secret_fields`, evaluated at call time.

    Returns:
        True when the CLI should offer and use secret storage.
    """
    return _has_secret_fields() and (
        str(getattr(schema_module, "CREDENTIAL_BACKEND", "prompt")) != "none"
    )


def _secrets_module() -> Any:
    """Import and return the secret-machinery module (``secrets.py``), lazily.

    Only called on paths that actually store or read secrets, so the CLI
    works without the module when the schema has no secret fields.

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
            "The settings schema declares secret fields, but the secret-storage machinery "
            "(secrets.py) has been removed from this package. Restore it (plus at least "
            'one *_backend.py module), or remove the "secret": True fields from the schema.'
        ) from exc


def _reserved_key_help() -> dict[str, str]:
    """Return the reserved backend keys mapped to help text, or ``{}``.

    Empty when the secret machinery has been removed from the package (there
    are then no reserved keys to set).

    Returns:
        ``{key: help text}`` for every reserved profile key.
    """
    module_name = f"{__package__}.secrets"
    try:
        secrets = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise  # secrets.py exists but something it imports is missing
        return {}
    help_map = dict(secrets.reserved_key_help())
    help_map.update(
        secrets.secret_name_help(
            {f.name: default_secret_name(f) for f in fields(Settings) if is_secret(f)}
        )
    )
    return help_map


# ---------------------------------------------------------------------------
# TOML document helpers (the only write path to config.toml)
# ---------------------------------------------------------------------------


def _load_document(path: Path) -> tomlkit.TOMLDocument:
    """Parse the config file, or return an empty document when absent.

    Args:
        path: Config file location.

    Returns:
        The parsed (comment-preserving) document.

    Raises:
        ConfigError: If the file exists but is not valid TOML.
    """
    if not path.exists():
        return tomlkit.document()
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except tomlkit.exceptions.ParseError as exc:
        raise ConfigError(f"Malformed TOML in {path}: {exc}") from exc


def _save_document(path: Path, document: tomlkit.TOMLDocument) -> None:
    """Write *document* to *path*, creating the config directory if needed.

    On POSIX the file is restricted to the owner (``0o600``); the directory
    permissions are handled by ``paths.ensure_config_dir``.

    Args:
        path: Config file location.
        document: The document to serialize.
    """
    paths.ensure_config_dir()
    path.write_text(document.as_string(), encoding="utf-8", newline="\n")
    if os.name == "posix":
        os.chmod(path, 0o600)


def _profile_table(
    document: tomlkit.TOMLDocument, profile: str | None, *, create: bool = False
) -> Any:
    """Return the table CLI edits target: a profile's table or the top level.

    Args:
        document: The parsed config document.
        profile: Profile name, or None for bare top-level mode.
        create: Create the ``[profiles.<name>]`` table when missing instead
            of failing (used by ``init``).

    Returns:
        A mutable tomlkit table.

    Raises:
        ConfigError: When the profile does not exist and *create* is False.
    """
    if profile is None:
        return document
    profiles = document.get("profiles")
    if profiles is None:
        if not create:
            raise ConfigError(
                f"Profile {profile!r} not found (no profiles defined). "
                f"Run '{CLI_NAME} init --profile {profile}' to create it."
            )
        profiles = tomlkit.table(True)
        document["profiles"] = profiles
    if profile not in profiles:
        if not create:
            available = ", ".join(sorted(profiles.keys())) or "none defined"
            raise ConfigError(
                f"Profile {profile!r} not found. Available profiles: {available}. "
                f"Run '{CLI_NAME} init --profile {profile}' to create it."
            )
        profiles[profile] = tomlkit.table()
    return profiles[profile]


def _schema_field(key: str, extra_valid: tuple[str, ...] = ()) -> Field[Any]:
    """Look up schema field *key*, failing loudly on unknown names.

    Args:
        key: A field name from the command line.
        extra_valid: Non-schema key names to include in the error's listing
            (the reserved backend keys, for commands that accept them).

    Returns:
        The matching dataclass field.

    Raises:
        ConfigError: When no such option exists, listing the valid names.
    """
    for f in fields(Settings):
        if f.name == key:
            return f
    valid = ", ".join([*(f.name for f in fields(Settings)), *extra_valid])
    raise ConfigError(f"Unknown option {key!r}. Valid options: {valid}.")


def _backend_config(
    document: tomlkit.TOMLDocument, profile: str | None, secrets: Any
) -> dict[str, Any]:
    """Return the merged reserved-key backend config for *profile*.

    Args:
        document: The parsed config document.
        profile: Active profile name, or None.
        secrets: The imported secret-machinery module.

    Returns:
        The merged reserved-key mapping (``credential_backend`` plus whatever
        each backend declares).
    """
    config: dict[str, Any] = dict(document)
    profiles = config.get("profiles")
    profile_values: dict[str, Any] = {}
    if profile is not None and isinstance(profiles, dict) and profile in profiles:
        profile_values = dict(profiles[profile])
    return dict(secrets.reserved_config(config, profile_values))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _prompt_backend_choice(table: Any, secrets: Any) -> None:
    """Interactively pick a credential backend and its config keys.

    Writes the choice (and any backend-declared keys the user fills in) into
    *table*; empty input skips, leaving no backend configured.

    Args:
        table: The mutable tomlkit table ``init`` is populating.
        secrets: The imported secret-machinery module.
    """
    available = secrets.available_backends()
    if not available:
        print("No credential backends are present in this package; skipping secret storage.")
        return
    names = ", ".join(available)
    while True:
        raw = input(
            f"{secrets.BACKEND_KEY} - where to store secrets ({names}; empty to skip): "
        ).strip()
        if not raw:
            return
        if raw in available:
            break
        print(f"Unknown backend {raw!r}. Available backends: {names}.")
    table[secrets.BACKEND_KEY] = raw
    _prompt_backend_keys(table, raw, {}, secrets)


def _prompt_backend_keys(table: Any, backend: str, already: dict[str, Any], secrets: Any) -> None:
    """Prompt for backend *backend*'s own config keys (e.g. a vault URL).

    Args:
        table: The mutable tomlkit table ``init`` is populating.
        backend: The selected backend's name.
        already: Reserved-key values already configured (skipped).
        secrets: The imported secret-machinery module.
    """
    for key, help_text in secrets.backend_reserved_keys(backend).items():
        if key in already:
            continue
        value = input(f"{key} - {help_text} (empty to skip): ").strip()
        if value:
            table[key] = value
        else:
            print(f"Skipped {key}; set it later with '{CLI_NAME} set {key} <value>'.")


def _confirm(prompt: str) -> bool:
    """Ask a yes/no question; empty input means no.

    Args:
        prompt: The question, shown as is.

    Returns:
        True for yes, False for no or empty input. Anything else asks again.
    """
    while True:
        raw = input(prompt).strip().lower()
        if not raw:
            return False
        if raw in _YES_NO:
            return _YES_NO[raw]
        print("Answer y or n.")


def _prompt_secret_names(table: Any, backend_config: dict[str, Any], secrets: Any) -> set[str]:
    """Prompt for each secret field's backend storage NAME (visible input).

    The name is not the secret, so it is echoed. Empty input keeps the
    offered default (an existing ``<field>_secret_name``, else the schema's
    ``default_secret_name``, else the field name). The result is always
    written to *table*: runtime resolution reads names from config.toml
    only, never from a fallback.

    Each optional secret is asked about first. Declining skips it entirely:
    no storage name is written, so it resolves as not set.

    Args:
        table: The mutable tomlkit table ``init`` is populating.
        backend_config: Merged reserved-key table for the target profile.
        secrets: The imported secret-machinery module.

    Returns:
        The names of the optional secrets the user declined.
    """
    declined: set[str] = set()
    for f in fields(Settings):
        if not is_secret(f):
            continue
        if not is_optional_secret(f):
            print(f"{f.name} - {field_help(f)}")
        elif not _confirm(f"{f.name} - {field_help(f)} (optional). Set it up now? [y/N]: "):
            print(f"Skipped {f.name}; set it up later with '{CLI_NAME} set-secret {f.name}'.")
            declined.add(f.name)
            continue
        name_key = secrets.secret_name_key(f.name)
        offered = backend_config.get(name_key) or default_secret_name(f) or f.name
        raw = input(
            f"  secret NAME in backend (visible, not the secret) [default: {offered}]: "
        ).strip()
        table[name_key] = raw or offered
    return declined


def _cmd_init(args: argparse.Namespace) -> int:
    """Interactively create the config file (and optionally a profile).

    Prompts for every schema field: non-secrets are written to config.toml
    (empty input keeps the default, or re-prompts when required). When the
    schema has secret fields, selects a credential backend -- the schema's
    ``CREDENTIAL_BACKEND`` default (announced, its own keys prompted for), or
    the user's pick under the ``"prompt"`` policy -- then collects each
    secret's backend storage NAME (visible; always persisted as
    ``<field>_secret_name``) and, on writable backends only,
    each secret VALUE via hidden prompts (empty input skips, with a
    reminder). An optional secret the user declines to set up gets neither
    prompt. Read-only backends get a pointer at where the values live;
    the ``"none"`` policy skips secret storage entirely. Refuses to touch an
    already-configured target so a typo cannot silently overwrite a tenant's
    settings.

    ``--force`` skips that refusal and starts from an empty document, so the
    saved file replaces the existing one whole: every profile and comment is
    dropped, and a malformed file is never parsed. The old file stays intact
    until that save, so an aborted run loses nothing. Secret values already
    in the backend are left there.

    Args:
        args: Parsed CLI arguments (``profile``, ``force``).

    Returns:
        Process exit code.
    """
    path = paths.config_path()
    document = tomlkit.document() if args.force else _load_document(path)
    table = _profile_table(document, args.profile, create=True)

    already = [f.name for f in fields(Settings) if f.name in table]
    if already:
        target = f"profile {args.profile!r}" if args.profile else f"the top level of {path}"
        raise ConfigError(
            f"{target} is already configured ({', '.join(already)}). "
            f"Use '{CLI_NAME} set' / '{CLI_NAME} set-secret' to change values, or "
            f"'{CLI_NAME} init --force' to start over with a new config file."
        )

    hints = get_type_hints(Settings)
    if args.force and path.exists():
        print(f"--force: starting over; the existing {path} will be replaced.")
    print(f"Writing {path}" + (f" (profile {args.profile!r})" if args.profile else ""))
    for f in fields(Settings):
        if is_secret(f):
            continue
        label = f"{f.name} - {field_help(f)}"
        if not is_required(f):
            label += f" [default: {field_default(f)!r}]"
        while True:
            raw = input(f"{label}: ").strip()
            if raw:
                table[f.name] = coerce_string(f.name, raw, hints[f.name])
                break
            if not is_required(f):
                break  # keep the schema default; write nothing
            print(f"{f.name} is required.")

    secrets = _secrets_module() if _secret_storage_active() else None
    declined: set[str] = set()
    if _has_secret_fields() and secrets is None:
        print(
            "schema.CREDENTIAL_BACKEND is 'none'; secrets are not stored. "
            "Provide them via environment variables."
        )
    if secrets is not None:
        backend_config = _backend_config(document, args.profile, secrets)
        selected = secrets.backend_name(backend_config)
        if selected is None:
            _prompt_backend_choice(table, secrets)
        elif secrets.BACKEND_KEY not in backend_config:
            print(f"Using credential backend {selected!r} (schema default).")
            _prompt_backend_keys(table, selected, backend_config, secrets)
        backend_config = _backend_config(document, args.profile, secrets)
        if secrets.backend_name(backend_config) is not None:
            declined = _prompt_secret_names(table, backend_config, secrets)
    _save_document(path, document)

    if secrets is not None:
        backend_config = _backend_config(document, args.profile, secrets)
        if secrets.backend_name(backend_config) is None:
            print(
                "No credential_backend chosen; secrets were not stored. Provide them via "
                f"environment variables, or pick a backend later with "
                f"'{CLI_NAME} set {secrets.BACKEND_KEY} <name>' and store them with "
                f"'{CLI_NAME} set-secret <key>'."
            )
        elif secrets.is_read_only(backend_config):
            print(secrets.read_only_notice(backend_config))
        else:
            for f in fields(Settings):
                if not is_secret(f) or f.name in declined:
                    continue
                value = getpass.getpass(f"{f.name} - secret VALUE (hidden, empty to skip): ")
                if value:
                    secrets.set_secret(f.name, value, args.profile, backend_config)
                    print(
                        f"Stored {f.name} in the {secrets.backend_name(backend_config)!r} backend."
                    )
                else:
                    print(
                        f"Skipped {f.name}; store it later with '{CLI_NAME} set-secret {f.name}'."
                    )

    print(f"Done. Inspect with '{CLI_NAME} show'.")
    return 0


def _cmd_path(args: argparse.Namespace) -> int:
    """Print the resolved config file path.

    Args:
        args: Parsed CLI arguments (unused).

    Returns:
        Process exit code.
    """
    print(paths.config_path())
    return 0


def _cmd_open(args: argparse.Namespace) -> int:
    """Open the config file in the program the OS associates with it.

    The OS picks the program: ``os.startfile`` on Windows, ``open`` on macOS,
    ``xdg-open`` elsewhere.

    Args:
        args: Parsed CLI arguments (unused).

    Returns:
        Process exit code.

    Raises:
        ConfigError: When the file does not exist yet, or, off Windows, the
            opener command is missing or fails.
    """
    path = paths.config_path()
    if not path.exists():
        raise ConfigError(f"No config file at {path}. Run '{CLI_NAME} init' to create it.")
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606  (opens a known file path, no shell)
    else:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        executable = shutil.which(opener)
        if executable is None:
            raise ConfigError(
                f"Could not open {path}: {opener!r} not found. Open the file directly."
            )
        result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
            [executable, str(path)], check=False
        )
        if result.returncode != 0:
            raise ConfigError(
                f"Could not open {path}: {opener!r} exited with status {result.returncode}."
            )
    print(f"Opened {path}")
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    """Print the effective configuration with provenance, secrets masked.

    An optional secret that no layer provides prints as None: there is no
    value to mask.

    Args:
        args: Parsed CLI arguments (``profile``).

    Returns:
        Process exit code.
    """
    settings, sources, profile_name = resolve_with_sources(Settings, profile=args.profile)
    print(f"config file: {paths.config_path()}")
    print(f"profile:     {profile_name or 'none (top-level keys)'}")
    width = max(len(f.name) for f in fields(Settings))
    for f in fields(Settings):
        value = getattr(settings, f.name)
        if is_secret(f) and value is not None:
            value = _SECRET_MASK
        print(f"  {f.name:<{width}} = {value!r}  <- {sources[f.name]}")
    return 0


def _reserved_value(key: str, value: str) -> str:
    """Validate *value* for the reserved backend key *key*.

    ``credential_backend`` must name an available backend; a
    ``<field>_secret_name`` key must be non-empty; every other reserved key
    is a free-form string the backend interprets itself.

    Args:
        key: A reserved backend key.
        value: The raw command-line value.

    Returns:
        The validated value.

    Raises:
        ConfigError: When ``credential_backend`` names no available backend,
            or a storage-name key is empty.
    """
    secrets = _secrets_module()
    if key == secrets.BACKEND_KEY and value not in secrets.available_backends():
        available = ", ".join(secrets.available_backends()) or "none"
        raise ConfigError(f"Unknown credential backend {value!r}. Available backends: {available}.")
    if key.endswith(secrets.SECRET_NAME_SUFFIX) and not value:
        raise ConfigError(f"{key!r} must be a non-empty backend storage name.")
    return value


def _cmd_set(args: argparse.Namespace) -> int:
    """Write a non-secret option or reserved backend key to config.toml.

    Comment-preserving. Reserved backend keys (``credential_backend`` and
    whatever each backend declares) are how the user picks and configures
    where secrets are stored.

    Args:
        args: Parsed CLI arguments (``key``, ``value``, ``profile``).

    Returns:
        Process exit code.

    Raises:
        ConfigError: For unknown or secret-classified keys, or an unknown
            backend name.
    """
    reserved = _reserved_key_help()
    if args.key in reserved:
        value: Any = _reserved_value(args.key, args.value)
    else:
        f = _schema_field(args.key, tuple(reserved))
        if is_secret(f):
            raise ConfigError(
                f"{args.key!r} is a secret and must never be written to config.toml. "
                f"Use '{CLI_NAME} set-secret {args.key}' instead."
            )
        value = coerce_string(args.key, args.value, get_type_hints(Settings)[args.key])
    path = paths.config_path()
    document = _load_document(path)
    table = _profile_table(document, args.profile)
    table[args.key] = value
    _save_document(path, document)
    where = f"profile {args.profile!r}" if args.profile else "top level"
    print(f"Set {args.key} = {value!r} ({where}) in {path}")
    return 0


def _cmd_unset(args: argparse.Namespace) -> int:
    """Remove an option from config.toml so the schema default applies.

    Also removes reserved backend keys (unsetting ``credential_backend``
    leaves the profile with no secret storage configured).

    Args:
        args: Parsed CLI arguments (``key``, ``profile``).

    Returns:
        Process exit code.

    Raises:
        ConfigError: When the key is not set in the targeted table.
    """
    reserved = _reserved_key_help()
    f = None if args.key in reserved else _schema_field(args.key, tuple(reserved))
    path = paths.config_path()
    document = _load_document(path)
    table = _profile_table(document, args.profile)
    if args.key not in table:
        where = f"profile {args.profile!r}" if args.profile else f"the top level of {path}"
        raise ConfigError(f"{args.key!r} is not set in {where}; nothing to unset.")
    del table[args.key]
    _save_document(path, document)
    print(f"Unset {args.key} in {path}")
    if f is not None and is_required(f):
        print(f"Note: {args.key} is required; resolution will fail until it is provided again.")
    return 0


def _cmd_list_profiles(args: argparse.Namespace) -> int:
    """List profile names, marking the default.

    Args:
        args: Parsed CLI arguments (unused).

    Returns:
        Process exit code.
    """
    document = _load_document(paths.config_path())
    profiles = document.get("profiles")
    default = document.get("default_profile")
    if not profiles:
        print("No profiles defined (bare top-level mode).")
        return 0
    for name in sorted(profiles.keys()):
        marker = "  (default)" if name == default else ""
        print(f"{name}{marker}")
    return 0


def _cmd_use(args: argparse.Namespace) -> int:
    """Set ``default_profile``.

    Args:
        args: Parsed CLI arguments (``profile``).

    Returns:
        Process exit code.

    Raises:
        ConfigError: When the named profile does not exist.
    """
    path = paths.config_path()
    document = _load_document(path)
    _profile_table(document, args.profile)  # existence check
    document["default_profile"] = args.profile
    _save_document(path, document)
    print(f"default_profile = {args.profile!r} in {path}")
    return 0


def _select_secret_profile(document: tomlkit.TOMLDocument, explicit: str | None) -> str | None:
    """Resolve which profile a secret command targets.

    Same order as settings resolution: explicit flag, then the profile env
    var, then ``default_profile``.

    Args:
        document: The parsed config document.
        explicit: The ``--profile`` value, if any.

    Returns:
        The profile name, or None for bare top-level mode.
    """
    return select_profile_name(explicit, dict(document), paths.config_path())


def _cmd_set_secret(args: argparse.Namespace) -> int:
    """Prompt for a secret's storage name (visible) and value (hidden).

    The NAME prompt echoes -- it is not the secret -- and the chosen name is
    persisted to config.toml as ``<key>_secret_name``. The VALUE prompt is
    hidden and only shown for writable backends; on a read-only backend the
    command stores nothing and instead points at where the value lives.

    Args:
        args: Parsed CLI arguments (``key``, ``profile``).

    Returns:
        Process exit code.

    Raises:
        ConfigError: For unknown or non-secret keys, no configured backend,
            or an empty value.
    """
    f = _schema_field(args.key)
    if not is_secret(f):
        raise ConfigError(
            f"{args.key!r} is not a secret. Use '{CLI_NAME} set {args.key} <value>' instead."
        )
    secrets = _secrets_module()
    path = paths.config_path()
    document = _load_document(path)
    profile = _select_secret_profile(document, args.profile)
    backend_config = _backend_config(document, profile, secrets)
    secrets.require_backend(backend_config, f"store secret {args.key!r}")

    name_key = secrets.secret_name_key(args.key)
    offered = backend_config.get(name_key) or default_secret_name(f) or args.key
    raw = input(
        f"{args.key} - secret NAME in backend (visible, not the secret) [default: {offered}]: "
    ).strip()
    chosen = raw or offered
    if backend_config.get(name_key) != chosen:
        table = _profile_table(document, profile)
        table[name_key] = chosen
        _save_document(path, document)
        backend_config = _backend_config(document, profile, secrets)
        print(f"Set {name_key} = {chosen!r} in {path}")

    if secrets.is_read_only(backend_config):
        print(secrets.read_only_notice(backend_config))
        return 0

    value = getpass.getpass(f"{args.key} - secret VALUE (hidden): ")
    if not value:
        raise ConfigError("Empty value; nothing stored.")
    secrets.set_secret(args.key, value, profile, backend_config)
    service = secrets.service_name(profile)
    backend = secrets.backend_name(backend_config)
    print(f"Stored {args.key} in the {backend!r} backend (service {service!r}).")
    return 0


def _cmd_delete_secret(args: argparse.Namespace) -> int:
    """Delete a secret from the backend.

    Args:
        args: Parsed CLI arguments (``key``, ``profile``).

    Returns:
        Process exit code.

    Raises:
        ConfigError: For unknown or non-secret keys, or a read-only backend.
    """
    f = _schema_field(args.key)
    if not is_secret(f):
        raise ConfigError(f"{args.key!r} is not a secret; use '{CLI_NAME} unset {args.key}'.")
    secrets = _secrets_module()
    document = _load_document(paths.config_path())
    profile = _select_secret_profile(document, args.profile)
    backend_config = _backend_config(document, profile, secrets)
    secrets.delete_secret(args.key, profile, backend_config)
    print(f"Deleted {args.key} from the {secrets.backend_name(backend_config)!r} backend.")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree.

    Returns:
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        prog=CLI_NAME,
        description="Create, inspect, and edit config.toml and stored secrets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, help_text: str, **kwargs: Any) -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help_text, description=help_text, **kwargs)

    p = add("init", "Interactive first-time setup.")
    p.add_argument("--profile", default=None, help="Create/populate this profile.")
    p.add_argument(
        "--force",
        action="store_true",
        help="Start over: replace the whole existing config file, every profile included.",
    )
    p.set_defaults(func=_cmd_init)

    p = add("path", "Print the config file path.")
    p.set_defaults(func=_cmd_path)

    p = add("open", "Open the config file in the OS's default program for it.")
    p.set_defaults(func=_cmd_open)

    p = add("show", "Show the effective config with provenance; secrets masked.")
    p.add_argument("--profile", default=None, help="Resolve this profile.")
    p.set_defaults(func=_cmd_show)

    p = add("set", "Set a non-secret option in config.toml.")
    p.add_argument("key")
    p.add_argument("value")
    p.add_argument("--profile", default=None, help="Target this profile's table.")
    p.set_defaults(func=_cmd_set)

    p = add("unset", "Remove an option so the schema default applies.")
    p.add_argument("key")
    p.add_argument("--profile", default=None, help="Target this profile's table.")
    p.set_defaults(func=_cmd_unset)

    p = add("list-profiles", "List profiles, marking the default.")
    p.set_defaults(func=_cmd_list_profiles)

    p = add("use", "Set default_profile.")
    p.add_argument("profile")
    p.set_defaults(func=_cmd_use)

    if _secret_storage_active():
        p = add("set-secret", "Prompt for a secret's name (visible) and value (hidden); store it.")
        p.add_argument("key")
        p.add_argument("--profile", default=None, help="Target this profile's backend.")
        p.set_defaults(func=_cmd_set_secret)

        p = add("delete-secret", "Delete a secret from the backend.")
        p.add_argument("key")
        p.add_argument("--profile", default=None, help="Target this profile's backend.")
        p.set_defaults(func=_cmd_delete_secret)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the config CLI.

    Args:
        argv: Argument list, or None to use ``sys.argv``.

    Returns:
        Process exit code (0 on success, 1 on any configuration error).
    """
    args = _build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
