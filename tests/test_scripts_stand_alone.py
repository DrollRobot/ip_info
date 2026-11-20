"""Every script in scripts/ stands alone: none imports another module from scripts/.

A script that shares a helper module with another can't be removed, or left out
of a project, without breaking the other. So each script carries the helpers it
uses, and pays for that in duplicated code.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.regression]

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

# Scripts allowed to import a sibling module. None.
ALLOWED: frozenset[str] = frozenset()


def imported_top_level_modules(source: str) -> set[str]:
    """Return the first component of every absolute import in ``source``."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_imported_top_level_modules() -> None:
    source = "import a.b\nfrom c.d import e\nfrom . import f\nimport g as h\n"
    assert imported_top_level_modules(source) == {"a", "c", "g"}


def test_no_script_imports_a_sibling() -> None:
    scripts = sorted(SCRIPTS.glob("*.py")) if SCRIPTS.is_dir() else []
    siblings = {path.stem for path in scripts}
    offenders = {
        path.name: sorted(imported_top_level_modules(path.read_text("utf-8")) & siblings)
        for path in scripts
        if path.name not in ALLOWED
    }
    assert {name: mods for name, mods in offenders.items() if mods} == {}
