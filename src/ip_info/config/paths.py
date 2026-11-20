r"""Config-file path resolution.

The config file lives in the OS-standard per-user configuration directory:

- Windows: ``%LOCALAPPDATA%\ip_info\config.toml``
- Linux:   ``~/.config/ip_info/config.toml`` (respects ``XDG_CONFIG_HOME``)
- macOS:   ``~/Library/Application Support/ip_info/config.toml``

``roaming=False`` is deliberate: roaming profiles / folder redirection would
replicate the config to network storage.

Set the ``<ENV_PREFIX>CONFIG_DIR`` environment variable to override the
directory entirely (used by tests and portable installs); tests must always
point it at a temporary directory so they never touch the real user config.
``ENV_PREFIX`` is defined in ``schema.py`` as the app name upper-cased plus
an underscore, so the variable's real name is :data:`CONFIG_DIR_ENV`.
"""

from __future__ import annotations

import os
from pathlib import Path

import platformdirs

from ip_info.config.schema import APP_NAME, ENV_PREFIX

# Environment variable overriding the config *directory* (not the file).
CONFIG_DIR_ENV = ENV_PREFIX + "CONFIG_DIR"

# File name inside the config directory.
CONFIG_FILE_NAME = "config.toml"


def config_dir() -> Path:
    """Return the directory that holds the config file.

    Returns:
        The ``CONFIG_DIR_ENV`` override when set, otherwise the OS-standard
        per-user config directory for :data:`APP_NAME`.
    """
    override = os.environ.get(CONFIG_DIR_ENV)
    if override:
        return Path(override)
    return Path(platformdirs.user_config_dir(APP_NAME, appauthor=False, roaming=False))


def config_path() -> Path:
    """Return the full path of the config file (which may not exist yet).

    Returns:
        ``config_dir() / "config.toml"``.
    """
    return config_dir() / CONFIG_FILE_NAME


def ensure_config_dir() -> Path:
    """Create the config directory if needed and return it.

    On POSIX the directory is restricted to the owner (``0o700``) with an
    explicit ``chmod`` so the umask cannot widen it. Windows needs no ACL
    work: the default ``%LOCALAPPDATA%`` ACL is already user-scoped.

    Returns:
        The config directory path.
    """
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(directory, 0o700)
    return directory
