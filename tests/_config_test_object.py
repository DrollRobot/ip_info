"""Shared settings test objects for the config unit tests.

The resolver engine is generic over any dataclass following the schema
conventions (see src/ip_info/config/schema.py). Tests run it
against these fixed test objects instead of the real ``Settings`` so they stay
green when a downstream repo replaces the FIXME example fields.

Three objects, so the generic tests never depend on secret storage:

- :class:`ConfigTestObject` -- every supported field type, no secret field.
  The generic resolution / validation / coercion / CLI tests use it, so they
  keep passing in a project whose schema declares no secrets and that deleted
  the secret-storage machinery.
- :class:`SecretTestObject` -- the same fields plus a required secret, for the
  tests that genuinely exercise secrets.
- :class:`OptionalSecretTestObject` -- :class:`SecretTestObject` plus an
  optional secret, for the tests of ``secret(required=False)``.

Also hosts :data:`requires_secret_storage`, the skip marker for tests that
need the machinery present; :func:`block_secrets_module`, which simulates
a project that deleted it (``config/secrets.py``), so the tests proving the
rest of the config system survives that removal can run without actually
deleting the file; and :func:`pin_prompt_policy`, which keeps the tests
independent of the project's own ``CREDENTIAL_BACKEND``.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from typing import Any

import pytest

_SECRETS_MODULE = "ip_info.config.secrets"
_SCHEMA_MODULE = "ip_info.config.schema"

# Skip marker for tests that need the secret-storage machinery itself: the
# backend dispatcher, the reserved backend keys, or the CREDENTIAL_BACKEND
# policy. Everything else must pass with or without it -- including the tests
# that simulate its removal with block_secrets_module(), which stay unmarked.
requires_secret_storage = pytest.mark.skipif(
    importlib.util.find_spec(_SECRETS_MODULE) is None,
    reason="secret-storage machinery (config/secrets.py) has been removed",
)


@dataclass(frozen=True)
class ConfigTestObject:
    """Secret-free schema exercising every supported field type."""

    name: str = field(metadata={"help": "Required plain string"})
    count: int = field(default=3, metadata={"help": "Defaulted int"})
    ratio: float = field(default=0.5, metadata={"help": "Defaulted float"})
    flag: bool = field(default=False, metadata={"help": "Defaulted bool"})
    tags: list[str] = field(default_factory=list, metadata={"help": "Defaulted list"})


@dataclass(frozen=True)
class SecretTestObject:
    """:class:`ConfigTestObject`'s fields plus a required secret.

    Field order matches ConfigTestObject's so both objects prompt for the
    same non-secret values, in the same order, during ``init``.
    """

    name: str = field(metadata={"help": "Required plain string"})
    token: str = field(repr=False, metadata={"secret": True, "help": "Required secret"})
    count: int = field(default=3, metadata={"help": "Defaulted int"})
    ratio: float = field(default=0.5, metadata={"help": "Defaulted float"})
    flag: bool = field(default=False, metadata={"help": "Defaulted bool"})
    tags: list[str] = field(default_factory=list, metadata={"help": "Defaulted list"})


@dataclass(frozen=True)
class OptionalSecretTestObject:
    """:class:`SecretTestObject`'s fields plus an optional secret, ``extra``.

    ``extra`` comes right after ``token``, so ``init`` asks about the
    secrets in that order, after the same non-secret values.
    """

    name: str = field(metadata={"help": "Required plain string"})
    token: str = field(repr=False, metadata={"secret": True, "help": "Required secret"})
    extra: str | None = field(
        default=None,
        repr=False,
        metadata={"secret": True, "optional": True, "help": "Optional secret"},
    )
    count: int = field(default=3, metadata={"help": "Defaulted int"})
    ratio: float = field(default=0.5, metadata={"help": "Defaulted float"})
    flag: bool = field(default=False, metadata={"help": "Defaulted bool"})
    tags: list[str] = field(default_factory=list, metadata={"help": "Defaulted list"})


class _BlockFinder:
    """Meta-path finder that refuses to import the secrets module."""

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
        if fullname == _SECRETS_MODULE:
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return None


def block_secrets_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make importing ``config/secrets.py`` fail as if the file were deleted.

    Drops any cached import (from ``sys.modules`` and the parent package's
    attribute) and installs a meta-path finder that raises
    ``ModuleNotFoundError`` for it, so every lazy-import path in the config
    system sees the module as absent. ``monkeypatch`` restores everything.

    Args:
        monkeypatch: The test's monkeypatch fixture.
    """
    import ip_info.config as config_package

    monkeypatch.delitem(sys.modules, _SECRETS_MODULE, raising=False)
    if hasattr(config_package, "secrets"):
        monkeypatch.delattr(config_package, "secrets")
    monkeypatch.setattr(sys, "meta_path", [_BlockFinder(), *sys.meta_path])


def pin_prompt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the schema's ``CREDENTIAL_BACKEND`` policy to ``"prompt"``.

    ``CREDENTIAL_BACKEND`` is the project's own constant, and every legal value
    changes what the config system does: a backend name sends secret lookups
    to that real store, and ``"none"`` drops the reserved backend keys and the
    secret commands. The config tests call this from an autouse fixture so
    they test the code, not the project's choice. ``"prompt"`` (no default
    backend) is the shipped value. Tests of another policy set it themselves,
    inside the test body, and still win.

    Args:
        monkeypatch: The test's monkeypatch fixture.
    """
    monkeypatch.setattr(f"{_SCHEMA_MODULE}.CREDENTIAL_BACKEND", "prompt")
