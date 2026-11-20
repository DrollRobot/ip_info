"""Tests for the config CLI (init / open / show / set / unset / profiles / secrets).

Commands run in-process via ``cli.main([...])`` with the config directory
pointed at ``tmp_path`` and the schema swapped for a fixed test object, so
nothing here touches the real user config, a real credential store (an
in-memory fake backend stands in), or the repo's FIXME example fields.

The default test object is secret-free, so every generic command test passes
in a project that removed the secret-storage machinery. Tests that exercise
secrets ask for the ``secret_schema`` fixture (which swaps in the test object
declaring one) and, when they also need the machinery itself, carry the
``requires_secret_storage`` skip marker.

The fake is a module registered in ``sys.modules`` under the name the
dispatcher imports, so the CLI reaches it through the real lookup in
``secrets.py``. Nothing here imports a concrete backend or its third-party
dependency, so this file keeps working in a project that deleted one.

An autouse fixture pins the schema's CREDENTIAL_BACKEND policy to "prompt"
(no default backend), whatever the project picked, so tests that store secrets
configure ``credential_backend`` explicitly (in the config file, or through
init's backend prompt); the fake registered as ``fake`` stands in for a real
store. Policy-specific tests monkeypatch the schema constant themselves.
"""

from __future__ import annotations

import os
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from ip_info.config import cli
from ip_info.config.paths import CONFIG_DIR_ENV
from ip_info.config.schema import APP_NAME, ENV_PREFIX, ConfigError
from tests._config_test_object import (
    ConfigTestObject,
    OptionalSecretTestObject,
    SecretTestObject,
    block_secrets_module,
    pin_prompt_policy,
    requires_secret_storage,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key)


@pytest.fixture(autouse=True)
def config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv(CONFIG_DIR_ENV, str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def _test_object_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run the CLI against the secret-free test object, not the FIXME fields."""
    monkeypatch.setattr("ip_info.config.cli.Settings", ConfigTestObject)


@pytest.fixture(autouse=True)
def _prompt_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test the CLI, not the project's CREDENTIAL_BACKEND choice."""
    pin_prompt_policy(monkeypatch)


@pytest.fixture
def secret_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a schema with a secret field.

    Requested by every test that exercises a secret. It runs after the
    autouse fixtures above (autouse fixtures are set up first within a scope),
    so the secret-bearing object wins for those tests only.
    """
    monkeypatch.setattr("ip_info.config.cli.Settings", SecretTestObject)


@pytest.fixture
def optional_secret_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install a schema with a required secret, ``token``, and an optional one, ``extra``."""
    monkeypatch.setattr("ip_info.config.cli.Settings", OptionalSecretTestObject)


def _install_backend(monkeypatch: pytest.MonkeyPatch, name: str, **functions: Any) -> None:
    """Register a fake ``<name>_backend`` module the dispatcher can import."""
    module = types.ModuleType(f"ip_info.config.{name}_backend")
    for attr, value in functions.items():
        setattr(module, attr, value)
    monkeypatch.setitem(sys.modules, module.__name__, module)


def _memory_backend(monkeypatch: pytest.MonkeyPatch, name: str) -> dict[tuple[str, str], str]:
    """Install a read-write in-memory backend and return its ``(service, key)`` store."""
    store: dict[tuple[str, str], str] = {}

    def delete(key: str, service: str, config: Any) -> None:
        # Mirrors the real backends' contract: deleting what is not there is
        # an error, never a silent no-op.
        if (service, key) not in store:
            raise ConfigError(f"No {key!r} stored for {service!r}; nothing deleted.")
        del store[(service, key)]

    _install_backend(
        monkeypatch,
        name,
        get=lambda key, service, config: store.get((service, key)),
        set=lambda key, value, service, config: store.__setitem__((service, key), value),
        delete=delete,
    )
    return store


@pytest.fixture(autouse=True)
def fake_backend(monkeypatch: pytest.MonkeyPatch) -> dict[tuple[str, str], str]:
    """In-memory backend named 'fake', so no test touches a real store.

    Registered in sys.modules, it shows up in available_backends() like a
    real backend file would, so init's backend prompt and the
    credential_backend validation accept it.
    """
    return _memory_backend(monkeypatch, "fake")


def _feed_input(monkeypatch: pytest.MonkeyPatch, responses: list[str]) -> None:
    answers = iter(responses)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))


def _feed_getpass(monkeypatch: pytest.MonkeyPatch, responses: list[str]) -> None:
    answers = iter(responses)
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))


def _forbid_getpass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if any hidden value prompt is shown."""

    def explode(prompt: str = "") -> str:
        raise AssertionError(f"unexpected hidden value prompt: {prompt!r}")

    monkeypatch.setattr("getpass.getpass", explode)


def _config_text(config_dir: Path) -> str:
    return (config_dir / "config.toml").read_text(encoding="utf-8")


# --- path ----------------------------------------------------------------------------


def test_path_prints_config_location(config_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["path"]) == 0
    assert str(config_dir / "config.toml") in capsys.readouterr().out


# --- open ----------------------------------------------------------------------------


def _fake_run(calls: list[list[str]], returncode: int = 0) -> Any:
    """Stand-in for ``subprocess.run`` that records argv instead of launching."""

    def run(argv: list[str], check: bool) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode)

    return run


def test_open_missing_file_points_at_init(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["open"]) == 1
    err = capsys.readouterr().err
    assert "No config file" in err
    assert "init" in err


def test_open_on_windows_uses_startfile(monkeypatch: pytest.MonkeyPatch, config_dir: Path) -> None:
    path = config_dir / "config.toml"
    path.write_text('name = "n"\n', encoding="utf-8")
    opened: list[Path] = []
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setattr("os.startfile", opened.append, raising=False)
    assert cli.main(["open"]) == 0
    assert opened == [path]


@pytest.mark.parametrize(("platform", "opener"), [("darwin", "open"), ("linux", "xdg-open")])
def test_open_on_posix_runs_the_platform_opener(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path, platform: str, opener: str
) -> None:
    path = config_dir / "config.toml"
    path.write_text('name = "n"\n', encoding="utf-8")
    calls: list[list[str]] = []
    monkeypatch.setattr("sys.platform", platform)
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", _fake_run(calls))
    assert cli.main(["open"]) == 0
    assert calls == [[f"/usr/bin/{opener}", str(path)]]


def test_open_without_opener_installed_is_actionable(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text('name = "n"\n', encoding="utf-8")
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert cli.main(["open"]) == 1
    assert "'xdg-open' not found" in capsys.readouterr().err


def test_open_opener_failure_is_reported(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text('name = "n"\n', encoding="utf-8")
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("subprocess.run", _fake_run([], returncode=4))
    assert cli.main(["open"]) == 1
    assert "exited with status 4" in capsys.readouterr().err


# --- init ----------------------------------------------------------------------------


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_writes_config_and_stores_secret(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # name, count, ratio, flag, tags -- empty keeps the default -- then the
    # backend choice, then token's storage name (empty keeps the field name).
    _feed_input(monkeypatch, ["n", "7", "", "", "", "fake", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0

    document = tomlkit.parse(_config_text(config_dir))
    assert document["name"] == "n"
    assert document["count"] == 7
    assert document["credential_backend"] == "fake"  # the user's choice is recorded
    assert "ratio" not in document  # empty input keeps the schema default
    assert "token" not in document  # secrets never reach the file
    # The storage name is always written; runtime reads it from config.toml only.
    assert document["token_secret_name"] == "token"  # noqa: S105  (a name, not a secret)
    assert fake_backend == {(APP_NAME, "token"): "tok"}
    assert "Stored token" in capsys.readouterr().out


@pytest.mark.integration
def test_init_required_field_reprompts(monkeypatch: pytest.MonkeyPatch, config_dir: Path) -> None:
    # First response empty for required 'name'; it must re-prompt. The rest
    # keep the defaults for count, ratio, flag, and tags.
    _feed_input(monkeypatch, ["", "n", "", "", "", ""])
    assert cli.main(["init"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["name"] == "n"


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_profile_scopes_secret_service(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init", "--profile", "p"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["profiles"]["p"]["name"] == "n"
    assert document["profiles"]["p"]["credential_backend"] == "fake"
    assert fake_backend == {(f"{APP_NAME}:p", "token"): "tok"}


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_rejects_unknown_backend_and_reprompts(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _feed_input(monkeypatch, ["n", "", "", "", "", "nope", "fake", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0
    assert "Unknown backend 'nope'" in capsys.readouterr().out
    assert tomlkit.parse(_config_text(config_dir))["credential_backend"] == "fake"


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_backend_skipped_prints_guidance_and_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _feed_input(monkeypatch, ["n", "", "", "", "", ""])
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert "No credential_backend chosen" in out
    assert "set credential_backend" in out
    assert fake_backend == {}
    assert "credential_backend" not in tomlkit.parse(_config_text(config_dir))


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_skips_backend_prompt_when_already_configured(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    # Only the schema fields and token's storage name are prompted; no
    # backend answer is queued.
    _feed_input(monkeypatch, ["n", "", "", "", "", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0
    assert fake_backend == {(APP_NAME, "token"): "tok"}


def test_init_refuses_configured_target(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text('name = "n"\n', encoding="utf-8")
    assert cli.main(["init"]) == 1
    err = capsys.readouterr().err
    assert "already configured" in err
    assert "init --force" in err


@pytest.mark.integration
def test_init_force_replaces_whole_file(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text(
        '# old comment\nname = "old"\ncount = 9\ndefault_profile = "p"\n\n'
        '[profiles.p]\nname = "pn"\n',
        encoding="utf-8",
    )
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    assert cli.main(["init", "--force"]) == 0
    text = _config_text(config_dir)
    assert tomlkit.parse(text).unwrap() == {"name": "n"}
    assert "# old comment" not in text
    assert "starting over" in capsys.readouterr().out


@pytest.mark.integration
def test_init_force_with_profile_still_replaces_whole_file(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path
) -> None:
    (config_dir / "config.toml").write_text(
        'name = "top"\n\n[profiles.p]\nname = "old"\n\n[profiles.q]\nname = "q"\n',
        encoding="utf-8",
    )
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    assert cli.main(["init", "--profile", "p", "--force"]) == 0
    assert tomlkit.parse(_config_text(config_dir)).unwrap() == {"profiles": {"p": {"name": "n"}}}


@pytest.mark.integration
def test_init_force_recovers_malformed_file(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path
) -> None:
    (config_dir / "config.toml").write_text("name = [unclosed\n", encoding="utf-8")
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    assert cli.main(["init", "--force"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["name"] == "n"


def test_init_force_aborted_keeps_old_file(
    monkeypatch: pytest.MonkeyPatch, config_dir: Path
) -> None:
    original = 'name = "old"\n'
    (config_dir / "config.toml").write_text(original, encoding="utf-8")

    def abort(prompt: str = "") -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", abort)
    with pytest.raises(KeyboardInterrupt):
        cli.main(["init", "--force"])
    assert _config_text(config_dir) == original


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_force_restarts_secret_setup_and_leaves_stored_values(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text(
        'name = "old"\ncredential_backend = "fake"\ntoken_secret_name = "old-name"\n',
        encoding="utf-8",
    )
    fake_backend[(APP_NAME, "old-name")] = "old-tok"
    # The backend choice is prompted again: nothing from the old file survives.
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init", "--force"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["credential_backend"] == "fake"
    assert document["token_secret_name"] == "token"  # noqa: S105  (a name, not a secret)
    assert fake_backend == {(APP_NAME, "old-name"): "old-tok", (APP_NAME, "token"): "tok"}


# --- set / unset ---------------------------------------------------------------------


def test_set_writes_coerced_value(config_dir: Path) -> None:
    assert cli.main(["set", "count", "7"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["count"] == 7


@pytest.mark.usefixtures("secret_schema")
def test_set_rejects_secret_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["set", "token", "x"]) == 1
    err = capsys.readouterr().err
    assert "never be written to config.toml" in err
    assert "set-secret token" in err


@requires_secret_storage
def test_set_rejects_unknown_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["set", "nope", "x"]) == 1
    err = capsys.readouterr().err
    assert "Unknown option 'nope'" in err
    assert "credential_backend" in err  # reserved keys join the listing


@requires_secret_storage
def test_set_credential_backend_rejects_unknown_backend(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["set", "credential_backend", "nope"]) == 1
    err = capsys.readouterr().err
    assert "Unknown credential backend 'nope'" in err
    assert "fake" in err  # the available backends are listed


@requires_secret_storage
def test_set_credential_backend_writes_choice(config_dir: Path) -> None:
    assert cli.main(["set", "credential_backend", "fake"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["credential_backend"] == "fake"


@requires_secret_storage
def test_set_backend_declared_key_writes(monkeypatch: pytest.MonkeyPatch, config_dir: Path) -> None:
    """Keys a backend declares in RESERVED_KEYS are settable while it exists."""
    _install_backend(
        monkeypatch,
        "vaulted",
        get=lambda key, service, config: None,
        RESERVED_KEYS={"vaulted_url": "Vault URL"},
    )
    assert cli.main(["set", "vaulted_url", "https://x.invalid/"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["vaulted_url"] == "https://x.invalid/"


@requires_secret_storage
def test_unset_credential_backend_removes_choice(
    config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    assert cli.main(["unset", "credential_backend"]) == 0
    out = capsys.readouterr().out
    assert "is required" not in out  # reserved keys are never schema-required
    assert "credential_backend" not in tomlkit.parse(_config_text(config_dir))


def test_set_unknown_profile_is_actionable(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["set", "count", "7", "--profile", "p"]) == 1
    assert "Profile 'p' not found" in capsys.readouterr().err


def test_set_preserves_comments(config_dir: Path) -> None:
    (config_dir / "config.toml").write_text('# keep me\nname = "n"\n', encoding="utf-8")
    assert cli.main(["set", "count", "7"]) == 0
    text = _config_text(config_dir)
    assert "# keep me" in text
    assert "count = 7" in text


def test_unset_removes_value_and_warns_when_required(
    config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text('name = "n"\n', encoding="utf-8")
    assert cli.main(["unset", "name"]) == 0
    out = capsys.readouterr().out
    assert "name is required" in out
    assert "name" not in tomlkit.parse(_config_text(config_dir))


def test_unset_missing_key_fails(config_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (config_dir / "config.toml").write_text('name = "n"\n', encoding="utf-8")
    assert cli.main(["unset", "count"]) == 1
    assert "nothing to unset" in capsys.readouterr().err


# --- profiles ------------------------------------------------------------------------


def test_list_profiles_bare_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["list-profiles"]) == 0
    assert "No profiles defined" in capsys.readouterr().out


def test_list_profiles_marks_default(config_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (config_dir / "config.toml").write_text(
        'default_profile = "b"\n[profiles.a]\n[profiles.b]\n', encoding="utf-8"
    )
    assert cli.main(["list-profiles"]) == 0
    out = capsys.readouterr().out
    assert "a" in out
    assert "b  (default)" in out


def test_use_sets_default_profile(config_dir: Path) -> None:
    (config_dir / "config.toml").write_text("[profiles.a]\n", encoding="utf-8")
    assert cli.main(["use", "a"]) == 0
    assert tomlkit.parse(_config_text(config_dir))["default_profile"] == "a"


def test_use_unknown_profile_fails(config_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (config_dir / "config.toml").write_text("[profiles.a]\n", encoding="utf-8")
    assert cli.main(["use", "b"]) == 1
    assert "Profile 'b' not found" in capsys.readouterr().err


# --- show ----------------------------------------------------------------------------


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_show_masks_secrets_and_reports_sources(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text(
        'name = "n"\ncredential_backend = "fake"\ntoken_secret_name = "token"\n', encoding="utf-8"
    )
    fake_backend[(APP_NAME, "token")] = "sekrit-value-xyz"
    monkeypatch.setenv(ENV_PREFIX + "COUNT", "9")
    assert cli.main(["show"]) == 0
    out = capsys.readouterr().out
    assert "sekrit-value-xyz" not in out  # masked
    assert "********" in out
    assert "<- fake" in out  # provenance names the user's backend
    assert "<- file:top-level" in out
    assert f"<- env:{ENV_PREFIX}COUNT" in out
    assert "<- default" in out


def test_show_missing_required_is_actionable(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["show"]) == 1
    assert "Missing required configuration value(s)" in capsys.readouterr().err


# --- secrets -------------------------------------------------------------------------


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_stores_via_backend(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    _feed_input(monkeypatch, [""])  # empty keeps the default storage name
    _feed_getpass(monkeypatch, ["s3"])
    assert cli.main(["set-secret", "token"]) == 0
    assert fake_backend == {(APP_NAME, "token"): "s3"}
    out = capsys.readouterr().out
    assert "s3" not in out  # value never echoed


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_without_backend_is_actionable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No credential_backend configured: fail fast, before any prompt."""
    _forbid_getpass(monkeypatch)
    assert cli.main(["set-secret", "token"]) == 1
    err = capsys.readouterr().err
    assert "no credential_backend is configured" in err
    assert "set credential_backend" in err


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_uses_default_profile_service(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text(
        'credential_backend = "fake"\ndefault_profile = "p"\n[profiles.p]\n', encoding="utf-8"
    )
    _feed_input(monkeypatch, [""])
    _feed_getpass(monkeypatch, ["s3"])
    assert cli.main(["set-secret", "token"]) == 0
    assert fake_backend == {(f"{APP_NAME}:p", "token"): "s3"}


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_rejects_empty_value(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    _feed_input(monkeypatch, [""])
    _feed_getpass(monkeypatch, [""])
    assert cli.main(["set-secret", "token"]) == 1
    assert "Empty value" in capsys.readouterr().err


@pytest.mark.usefixtures("secret_schema")
def test_set_secret_rejects_non_secret_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["set-secret", "name"]) == 1
    assert "not a secret" in capsys.readouterr().err


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_delete_secret_removes_stored_value(
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text(
        'credential_backend = "fake"\ntoken_secret_name = "token"\n', encoding="utf-8"
    )
    fake_backend[(APP_NAME, "token")] = "s3"
    assert cli.main(["delete-secret", "token"]) == 0
    assert fake_backend == {}


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_delete_secret_missing_fails_loudly(
    config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text(
        'credential_backend = "fake"\ntoken_secret_name = "token"\n', encoding="utf-8"
    )
    assert cli.main(["delete-secret", "token"]) == 1
    assert "nothing deleted" in capsys.readouterr().err


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_delete_secret_without_storage_name_is_actionable(
    config_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    assert cli.main(["delete-secret", "token"]) == 1
    assert "'token_secret_name' is not set" in capsys.readouterr().err


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_on_read_only_backend_names_the_manual_route(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A backend with no set() is read-only: set-secret becomes a name-only
    # operation -- no hidden value prompt, ever -- and surfaces the backend's
    # own READ_ONLY_HINT. Which backends are read-only is the backends'
    # business, tested with them.
    _install_backend(
        monkeypatch,
        "vaulted",
        get=lambda key, service, config: None,
        READ_ONLY_HINT="update the secret in the vault console",
    )
    (config_dir / "config.toml").write_text('credential_backend = "vaulted"\n', encoding="utf-8")
    _feed_input(monkeypatch, ["vault-token"])
    _forbid_getpass(monkeypatch)
    assert cli.main(["set-secret", "token"]) == 0
    out = capsys.readouterr().out
    assert "read-only" in out
    assert "update the secret in the vault console" in out
    document = tomlkit.parse(_config_text(config_dir))
    assert document["token_secret_name"] == "vault-token"  # noqa: S105  (a name, not a secret)


# --- secret storage names ------------------------------------------------------------


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_custom_secret_name_persists_and_scopes_storage(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    """A custom NAME lands in config.toml and the value is stored under it."""
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", "kv-token"])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["token_secret_name"] == "kv-token"  # noqa: S105  (a name, not a secret)
    assert fake_backend == {(APP_NAME, "kv-token"): "tok"}


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_set_secret_custom_name_persists_and_scopes_storage(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    _feed_input(monkeypatch, ["kv-token"])
    _feed_getpass(monkeypatch, ["s3"])
    assert cli.main(["set-secret", "token"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["token_secret_name"] == "kv-token"  # noqa: S105  (a name, not a secret)
    assert fake_backend == {(APP_NAME, "kv-token"): "s3"}
    assert "token_secret_name" in capsys.readouterr().out


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_delete_secret_uses_custom_name(
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    (config_dir / "config.toml").write_text(
        'credential_backend = "fake"\ntoken_secret_name = "kv-token"\n', encoding="utf-8"
    )
    fake_backend[(APP_NAME, "kv-token")] = "s3"
    assert cli.main(["delete-secret", "token"]) == 0
    assert fake_backend == {}


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_accepts_secret_name_key(config_dir: Path) -> None:
    """<field>_secret_name is a reserved key the set/unset commands accept."""
    assert cli.main(["set", "token_secret_name", "kv-token"]) == 0
    parsed = tomlkit.parse(_config_text(config_dir))
    assert parsed["token_secret_name"] == "kv-token"  # noqa: S105  (a name, not a secret)
    assert cli.main(["unset", "token_secret_name"]) == 0
    assert "token_secret_name" not in tomlkit.parse(_config_text(config_dir))


@requires_secret_storage
@pytest.mark.usefixtures("secret_schema")
def test_set_rejects_empty_secret_name(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["set", "token_secret_name", ""]) == 1
    assert "non-empty" in capsys.readouterr().err


@requires_secret_storage
@pytest.mark.integration
def test_set_secret_honors_schema_default_secret_name(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    """A schema default_secret_name scopes storage without any config.toml override."""
    from dataclasses import dataclass, field

    from ip_info.config.schema import secret

    @dataclass(frozen=True)
    class NamedSecretObject:
        name: str = field(metadata={"help": "Required plain string"})
        token: str = secret(
            help="Named secret",
            default_secret_name="kv-token",  # noqa: S106  (a name, not a secret)
        )

    monkeypatch.setattr("ip_info.config.cli.Settings", NamedSecretObject)
    (config_dir / "config.toml").write_text('credential_backend = "fake"\n', encoding="utf-8")
    _feed_input(monkeypatch, [""])  # empty accepts the schema's offered name
    _feed_getpass(monkeypatch, ["s3"])
    assert cli.main(["set-secret", "token"]) == 0
    assert fake_backend == {(APP_NAME, "kv-token"): "s3"}
    # The chosen name is persisted; runtime reads config.toml only.
    parsed = tomlkit.parse(_config_text(config_dir))
    assert parsed["token_secret_name"] == "kv-token"  # noqa: S105  (a name, not a secret)


# --- schema backend policy -----------------------------------------------------------


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_schema_default_backend_skips_choice_prompt(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A backend-name policy is used without prompting and never written."""
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "fake")
    # Schema fields, then token's storage name; no backend answer is queued.
    _feed_input(monkeypatch, ["n", "", "", "", "", ""])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert "Using credential backend 'fake' (schema default)" in out
    assert "credential_backend" not in tomlkit.parse(_config_text(config_dir))
    assert fake_backend == {(APP_NAME, "token"): "tok"}


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_read_only_backend_prompts_name_only(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Read-only backend: storage-name prompt only, never a value prompt."""
    _install_backend(
        monkeypatch,
        "vaulted",
        get=lambda key, service, config: None,
        READ_ONLY_HINT="update the secret in the vault console",
    )
    (config_dir / "config.toml").write_text('credential_backend = "vaulted"\n', encoding="utf-8")
    _feed_input(monkeypatch, ["n", "", "", "", "", "vault-token"])
    _forbid_getpass(monkeypatch)
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert "read-only" in out
    assert "update the secret in the vault console" in out
    parsed = tomlkit.parse(_config_text(config_dir))
    assert parsed["token_secret_name"] == "vault-token"  # noqa: S105  (a name, not a secret)


@pytest.mark.integration
@pytest.mark.usefixtures("secret_schema")
def test_init_none_policy_skips_secret_storage(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The 'none' policy prompts for nothing secret-related and stores nothing."""
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "none")
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    _forbid_getpass(monkeypatch)
    assert cli.main(["init"]) == 0
    out = capsys.readouterr().out
    assert "CREDENTIAL_BACKEND is 'none'" in out
    assert "environment variables" in out
    assert fake_backend == {}
    assert "credential_backend" not in tomlkit.parse(_config_text(config_dir))


@pytest.mark.usefixtures("secret_schema")
def test_none_policy_unregisters_secret_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Secret fields but a 'none' policy: the secret commands stay unregistered."""
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "none")
    with pytest.raises(SystemExit):
        cli.main(["set-secret", "token"])
    assert "invalid choice: 'set-secret'" in capsys.readouterr().err


# --- optional secret machinery -------------------------------------------------------


def test_secret_commands_absent_without_secret_fields(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A schema with no secret fields gets no set-secret/delete-secret commands."""
    with pytest.raises(SystemExit):
        cli.main(["set-secret", "token"])
    assert "invalid choice: 'set-secret'" in capsys.readouterr().err


@pytest.mark.usefixtures("secret_schema")
def test_set_secret_with_machinery_removed_is_actionable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Secret fields still in the schema after removal fail loudly, not weirdly."""
    block_secrets_module(monkeypatch)
    _feed_getpass(monkeypatch, ["s3"])
    assert cli.main(["set-secret", "token"]) == 1
    assert "secret-storage machinery" in capsys.readouterr().err


def test_backend_keys_unknown_when_machinery_removed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With secrets.py gone there are no reserved keys for set to accept."""
    block_secrets_module(monkeypatch)
    assert cli.main(["set", "credential_backend", "fake"]) == 1
    assert "Unknown option 'credential_backend'" in capsys.readouterr().err


# --- call-time schema gates ----------------------------------------------------------


@pytest.mark.regression
def test_secret_command_registration_follows_the_live_schema(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Swapping the schema mid-process changes which commands exist.

    Guards against reintroducing an import-time snapshot of the schema: the
    parser used to be built from flags computed once, at import, so a
    downstream secret-free schema silently kept (or lost) the secret
    commands regardless of what the tests installed.
    """
    with pytest.raises(SystemExit):  # secret-free schema: no such command
        cli.main(["set-secret", "token"])
    assert "invalid choice: 'set-secret'" in capsys.readouterr().err

    monkeypatch.setattr(cli, "Settings", SecretTestObject)
    # Registered now: the command parses and reaches its own error path
    # (no backend configured) instead of argparse's "invalid choice".
    assert cli.main(["set-secret", "token"]) == 1
    assert "invalid choice" not in capsys.readouterr().err


@pytest.mark.integration
@pytest.mark.regression
def test_init_secret_handling_follows_the_live_schema(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """init reads the schema at call time, so a mid-process swap is honored."""
    monkeypatch.setattr("ip_info.config.schema.CREDENTIAL_BACKEND", "none")
    _forbid_getpass(monkeypatch)
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    assert cli.main(["init"]) == 0
    assert "CREDENTIAL_BACKEND is 'none'" not in capsys.readouterr().out

    monkeypatch.setattr(cli, "Settings", SecretTestObject)
    _feed_input(monkeypatch, ["n", "", "", "", ""])
    assert cli.main(["init", "--profile", "p"]) == 0
    assert "CREDENTIAL_BACKEND is 'none'" in capsys.readouterr().out


# --- file permissions ----------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_saved_config_is_owner_only(config_dir: Path) -> None:
    assert cli.main(["set", "count", "7"]) == 0
    mode = (config_dir / "config.toml").stat().st_mode & 0o777
    assert mode == 0o600


# --- optional secrets ----------------------------------------------------------------


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("optional_secret_schema")
def test_init_declined_optional_secret_gets_no_name_and_no_value(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # name, count, ratio, flag, tags, backend, token's storage name, then
    # "set up extra?" left empty, which means no.
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", "", ""])
    _feed_getpass(monkeypatch, ["tok"])  # token's value only; no prompt for extra
    assert cli.main(["init"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["token_secret_name"] == "token"  # noqa: S105  (a name, not a secret)
    assert "extra_secret_name" not in document  # declined: resolves as not set
    assert fake_backend == {(APP_NAME, "token"): "tok"}
    assert "Skipped extra; set it up later with" in capsys.readouterr().out


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("optional_secret_schema")
def test_init_accepted_optional_secret_gets_name_and_value(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
) -> None:
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", "", "y", "kv-extra"])
    _feed_getpass(monkeypatch, ["tok", "ex"])
    assert cli.main(["init"]) == 0
    document = tomlkit.parse(_config_text(config_dir))
    assert document["extra_secret_name"] == "kv-extra"  # noqa: S105  (a name, not a secret)
    assert fake_backend == {(APP_NAME, "token"): "tok", (APP_NAME, "kv-extra"): "ex"}


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("optional_secret_schema")
def test_init_optional_secret_question_reprompts_on_other_answers(
    monkeypatch: pytest.MonkeyPatch,
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    _feed_input(monkeypatch, ["n", "", "", "", "", "fake", "", "maybe", "NO"])
    _feed_getpass(monkeypatch, ["tok"])
    assert cli.main(["init"]) == 0
    assert "Answer y or n." in capsys.readouterr().out
    assert "extra_secret_name" not in tomlkit.parse(_config_text(config_dir))


@requires_secret_storage
@pytest.mark.integration
@pytest.mark.usefixtures("optional_secret_schema")
def test_show_unset_optional_secret_is_none_and_set_one_is_masked(
    config_dir: Path,
    fake_backend: dict[tuple[str, str], str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    base = 'name = "n"\ncredential_backend = "fake"\ntoken_secret_name = "token"\n'
    (config_dir / "config.toml").write_text(base, encoding="utf-8")
    fake_backend[(APP_NAME, "token")] = "tok"
    assert cli.main(["show"]) == 0
    lines = capsys.readouterr().out.splitlines()
    extra_line = next(line for line in lines if line.strip().startswith("extra"))
    assert extra_line.endswith("= None  <- not set")

    (config_dir / "config.toml").write_text(
        base + 'extra_secret_name = "extra"\n', encoding="utf-8"
    )
    fake_backend[(APP_NAME, "extra")] = "extra-sekrit-xyz"
    assert cli.main(["show"]) == 0
    out = capsys.readouterr().out
    assert "extra-sekrit-xyz" not in out
    extra_line = next(line for line in out.splitlines() if line.strip().startswith("extra"))
    assert extra_line.endswith("= '********'  <- fake")
