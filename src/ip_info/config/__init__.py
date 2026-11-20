"""Configuration for ip_info.

Public API::

    from ip_info.config import Settings, load_settings

    settings = load_settings(profile="contoso")
    settings.api_url

Non-secret values live in a per-user ``config.toml`` (see ``paths.py`` for
the OS-specific location); secrets live in whichever credential backend the
user selects (``credential_backend`` in config.toml) and are never written
to the file. The config CLI creates and edits the file; no hand-editing is
required.

Module map (each module's docstring carries its own removal instructions
where applicable):

- ``schema.py``  - the ``Settings`` dataclass: single source of truth for
  option names, types, defaults, secret classification, and help text.
- ``paths.py``   - config-directory resolution.
- ``file.py``    - config.toml reading and validation.
- ``resolve.py`` - the precedence engine behind :func:`load_settings`.
- ``secrets.py`` + ``*_backend.py`` - optional secret-storage machinery:
  the backend dispatcher and the individual credential backends. Only
  consulted when the schema marks fields ``secret``; deletable as a unit
  when it marks none.
"""

from __future__ import annotations

from ip_info.config.resolve import load_settings, resolve_settings
from ip_info.config.schema import APP_NAME, CLI_NAME, ConfigError, Settings

__all__ = [
    "APP_NAME",
    "CLI_NAME",
    "ConfigError",
    "Settings",
    "load_settings",
    "resolve_settings",
]
