"""Guard against mypy config that silences imports with published type stubs.

When mypy reports 'Library stubs not installed for "X"', the correct fix is to
install the stub package it names (e.g. types-tabulate), not to silence the
module in pyproject.toml. This test reads the [tool.mypy] config and fails if
any silencing mechanism covers a module whose stubs are published on PyPI. It
consults mypy.stubinfo, the same registry mypy uses to print those hints, so
it works offline and stays in sync with the installed mypy version.

Caveat: mypy.stubinfo is internal to mypy, not a public API. The canary test
below fails loudly if an upgrade changes its behavior; if that happens, update
this module to the new API instead of deleting the guard.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from mypy.stubinfo import stub_distribution_name

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

# Error codes that, when disabled, hide missing-stub diagnostics.
_IMPORT_ERROR_CODES = {"import", "import-not-found", "import-untyped"}
# Boolean settings that make mypy accept imports without stubs.
_SILENCING_FLAGS = ("ignore_missing_imports", "follow_untyped_imports")


def _mypy_config() -> dict[str, Any]:
    """Return the [tool.mypy] table from pyproject.toml."""
    with _PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)
    config = pyproject["tool"]["mypy"]  # KeyError here means the section was removed
    assert isinstance(config, dict)
    return config


def _silences_imports(section: dict[str, Any]) -> bool:
    """Report whether a mypy config section suppresses missing-stub errors."""
    if any(section.get(flag) for flag in _SILENCING_FLAGS):
        return True
    disabled = section.get("disable_error_code", [])
    if isinstance(disabled, str):
        disabled = [disabled]
    return bool(_IMPORT_ERROR_CODES.intersection(disabled))


def test_stubinfo_canary() -> None:
    """Fail loudly if mypy's internal stub registry API changes semantics."""
    assert stub_distribution_name("tabulate") == "types-tabulate"
    assert stub_distribution_name("pytest") is None


def test_global_mypy_config_does_not_silence_imports() -> None:
    """The global [tool.mypy] table must not suppress missing-stub errors."""
    assert not _silences_imports(_mypy_config()), (
        "[tool.mypy] globally silences missing/untyped imports. Remove the "
        "setting; if a specific dependency ships no types and has no stub "
        "package, add a narrow [[tool.mypy.overrides]] entry for it instead."
    )


def test_overrides_do_not_silence_modules_with_published_stubs() -> None:
    """Every silenced override module must lack a published stub package."""
    silenced: list[str] = []
    for override in _mypy_config().get("overrides", []):
        if not _silences_imports(override):
            continue
        module = override["module"]
        silenced.extend([module] if isinstance(module, str) else module)

    offenders = {
        module: distribution
        for module in silenced
        if (distribution := stub_distribution_name(module.split(".")[0]))
    }
    assert not offenders, (
        "pyproject.toml silences mypy for modules that have published type "
        "stubs. Install the stub package (dev dependency group) and delete "
        f"the override instead: {offenders}"
    )
