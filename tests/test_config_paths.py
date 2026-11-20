"""Unit tests for config-directory resolution in config/paths.py."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ip_info.config import paths
from ip_info.config.schema import APP_NAME, ENV_PREFIX

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip all of this package's env vars so tests control every input."""
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key)


def test_env_override_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv(paths.CONFIG_DIR_ENV, str(tmp_path))
    assert paths.config_dir() == tmp_path
    assert paths.config_path() == tmp_path / "config.toml"


def test_default_dir_is_app_scoped_and_absolute() -> None:
    directory = paths.config_dir()
    assert directory.is_absolute()
    assert APP_NAME in directory.parts


def test_ensure_config_dir_creates_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "nested" / "config-home"
    monkeypatch.setenv(paths.CONFIG_DIR_ENV, str(target))
    created = paths.ensure_config_dir()
    assert created == target
    assert target.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_ensure_config_dir_is_owner_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "config-home"
    monkeypatch.setenv(paths.CONFIG_DIR_ENV, str(target))
    paths.ensure_config_dir()
    assert (target.stat().st_mode & 0o777) == 0o700
