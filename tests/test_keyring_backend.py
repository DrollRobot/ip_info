"""Unit tests for the OS-keyring credential backend.

Keyring is exercised against monkeypatched keyring functions -- never the
host's real credential store; the real-store roundtrip is a live-marked test.
The fake store also stubs ``keyring.get_keyring`` so the backend's usable-
backend check passes on headless hosts (CI, containers), where the real
``get_keyring`` returns a fail backend.

This module imports the keyring backend and the ``keyring`` package at module
scope, so it is deleted along with the backend when a project drops it.
"""

from __future__ import annotations

import sys
from typing import Any

import keyring
import keyring.backends.fail
import pytest

from ip_info.config import keyring_backend
from ip_info.config.schema import APP_NAME, ConfigError

pytestmark = pytest.mark.unit


class _UsableBackend:
    """Stand-in for a working OS keyring, so the usable-backend check passes.

    The check only rejects fail and empty-chainer backends, and nothing calls
    this object's methods -- the fixture patches the module-level functions.
    """


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    """Replace the keyring module functions with an in-memory store.

    Also stubs ``keyring.get_keyring`` with a usable backend, so the tests
    pass on headless hosts where the real one resolves to a fail backend.
    """
    store: dict[tuple[str, str], str] = {}

    def delete(service: str, key: str) -> None:
        if (service, key) not in store:
            raise keyring.errors.PasswordDeleteError(key)
        del store[(service, key)]

    usable = _UsableBackend()
    monkeypatch.setattr(keyring, "get_keyring", lambda: usable)
    monkeypatch.setattr(keyring, "get_password", lambda service, key: store.get((service, key)))

    def set_password(service: str, key: str, value: str) -> None:
        store[(service, key)] = value

    monkeypatch.setattr(keyring, "set_password", set_password)
    monkeypatch.setattr(keyring, "delete_password", delete)
    return store


def test_keyring_roundtrip_with_fake_store(fake_keyring: dict[tuple[str, str], str]) -> None:
    keyring_backend.set("token", "s", "svc", {})
    assert fake_keyring == {("svc", "token"): "s"}
    assert keyring_backend.get("token", "svc", {}) == "s"
    keyring_backend.delete("token", "svc", {})
    assert keyring_backend.get("token", "svc", {}) is None


def test_keyring_delete_missing_fails_loudly(fake_keyring: dict[tuple[str, str], str]) -> None:
    with pytest.raises(ConfigError, match="nothing deleted"):
        keyring_backend.delete("token", "svc", {})


def test_keyring_headless_backend_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    fail_backend = keyring.backends.fail.Keyring()  # type: ignore[no-untyped-call]
    monkeypatch.setattr(keyring, "get_keyring", lambda: fail_backend)
    with pytest.raises(ConfigError, match=r"No usable OS keyring.*environment variables"):
        keyring_backend.get("token", "svc", {})


def test_keyring_declares_no_reserved_keys() -> None:
    """The OS keyring needs no config.toml keys beyond credential_backend."""
    assert keyring_backend.RESERVED_KEYS == {}


def test_missing_keyring_package_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the optional 'keyring' package the error names how to get it."""

    class BlockKeyring:
        def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
            if fullname == "keyring" or fullname.startswith("keyring."):
                raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
            return None

    for name in list(sys.modules):
        if name == "keyring" or name.startswith("keyring."):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "meta_path", [BlockKeyring(), *sys.meta_path])
    with pytest.raises(ConfigError, match=r"'keyring' extra"):
        keyring_backend.get("token", "svc", {})


# --- live ----------------------------------------------------------------------------


@pytest.mark.live
@pytest.mark.integration
def test_real_keyring_roundtrip() -> None:
    """Store, read, and delete a value in the host's real credential store."""
    service = f"{APP_NAME}:pytest-live"
    key = "live-roundtrip-probe"
    keyring_backend.set(key, "probe-value", service, {})
    try:
        assert keyring_backend.get(key, service, {}) == "probe-value"
    finally:
        keyring_backend.delete(key, service, {})
    assert keyring_backend.get(key, service, {}) is None
