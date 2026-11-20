"""Require every .secrets.baseline entry to be an audited false positive.

The ``detect-secrets`` pre-commit hook only proves that every finding in the
staged files has a matching ``.secrets.baseline`` entry -- it says nothing
about whether anyone audited that entry. That leaves one easy hole: blindly
regenerating the baseline with ``detect-secrets scan`` records a real secret
as an UNVERIFIED entry, and the membership check passes.

This gate closes that hole. It runs at commit time (the
``secrets-baseline-audited`` pre-commit hook) and in the regular test suite,
and fails unless every baseline entry carries ``is_secret: false`` -- the
state ``detect-secrets audit`` writes when a human marks a finding as a false
positive. ``is_secret: true`` (a confirmed real secret) and a missing or null
``is_secret`` (never reviewed) both fail.

"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

BASELINE_NAME = ".secrets.baseline"

_GUIDANCE = (
    "Audit new baseline entries and remove any real secrets:\n"
    "  uv run detect-secrets audit .secrets.baseline\n"
)


def _find_root() -> Path:
    """Locate the repository root by walking up to the ``pyproject.toml`` marker.

    Starts from this file's directory, so the answer does not depend on the
    process working directory.

    Deliberately does not ask git, as ``test_no_inline_suppressions_for_secrets``
    does not either. git exports its own environment to the hooks it runs, and
    an inherited ``GIT_DIR`` makes ``rev-parse --show-toplevel`` report the
    current directory as the top of the work tree instead of discovering the
    real root -- which pointed this gate at ``tests/`` whenever it ran from a
    worktree's commit hook, and failed the commit. Walking to a marker file has
    no environment to inherit and does not need git installed.
    """
    root = Path(__file__).resolve().parent
    while root != root.parent:
        if (root / "pyproject.toml").exists():
            return root
        root = root.parent
    raise RuntimeError("Could not find project root (no pyproject.toml found)")


_ROOT = _find_root()


def _unaudited_entries(baseline_text: str) -> list[str]:
    """List baseline entries that are not audited false positives.

    An entry is acceptable only with ``is_secret: false`` (the state
    ``detect-secrets audit`` writes when a human marks it a false positive).
    ``is_secret: true`` means a human confirmed a real secret is in the repo;
    a missing/null ``is_secret`` means nobody has looked at all.

    Args:
        baseline_text: JSON text of a ``.secrets.baseline`` file.

    Returns:
        One ``path:line: CATEGORY (type)`` string per unaudited entry.
    """
    results: dict[str, list[dict[str, object]]] = json.loads(baseline_text).get("results", {})
    problems: list[str] = []
    for filename, entries in results.items():
        for entry in entries:
            is_secret = entry.get("is_secret")
            if is_secret is False:
                continue
            category = "VERIFIED_TRUE" if is_secret is True else "UNVERIFIED"
            problems.append(
                f"{filename}:{entry.get('line_number')}: {category} ({entry.get('type')})"
            )
    return problems


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.functional
def test_baseline_is_fully_audited() -> None:
    """Every entry in the repo's .secrets.baseline is an audited false positive.

    During a ``git commit``, pre-commit has stashed unstaged changes, so the
    baseline on disk is what is being committed: the commit that introduces an
    unaudited entry fails while the context is fresh.
    """
    baseline = _ROOT / BASELINE_NAME
    if not baseline.exists():
        pytest.fail(f"{BASELINE_NAME} is missing from the repo root", pytrace=False)
    problems = _unaudited_entries(baseline.read_text(encoding="utf-8"))
    if problems:
        listing = "\n".join(f"  {p}" for p in problems)
        pytest.fail(
            f"{len(problems)} unaudited baseline entr(y/ies):\n{listing}\n\n{_GUIDANCE}",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------


def _baseline_json(*entries: dict[str, object]) -> str:
    return json.dumps({"results": {"some/file.py": list(entries)}})


@pytest.mark.unit
def test_audited_false_positive_is_accepted() -> None:
    text = _baseline_json({"is_secret": False, "line_number": 3, "type": "Secret Keyword"})
    assert _unaudited_entries(text) == []


@pytest.mark.unit
def test_unreviewed_entry_is_flagged_unverified() -> None:
    text = _baseline_json({"line_number": 3, "type": "Secret Keyword"})
    assert _unaudited_entries(text) == ["some/file.py:3: UNVERIFIED (Secret Keyword)"]


@pytest.mark.unit
def test_null_is_secret_is_flagged_unverified() -> None:
    text = _baseline_json({"is_secret": None, "line_number": 9, "type": "Hex High Entropy String"})
    assert _unaudited_entries(text) == ["some/file.py:9: UNVERIFIED (Hex High Entropy String)"]


@pytest.mark.unit
def test_confirmed_real_secret_is_flagged_verified_true() -> None:
    text = _baseline_json({"is_secret": True, "line_number": 5, "type": "AWS Access Key"})
    assert _unaudited_entries(text) == ["some/file.py:5: VERIFIED_TRUE (AWS Access Key)"]


@pytest.mark.unit
def test_empty_baseline_results_are_accepted() -> None:
    assert _unaudited_entries(json.dumps({"results": {}})) == []
