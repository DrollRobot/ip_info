"""Run detect-secrets' pre-commit hook with file paths in the local OS style.

detect-secrets 1.5.0 converts every path it scans, and every path it loads from
the baseline, to the local separator -- backslashes on Windows. The list of
files the hook was handed is the one thing it leaves alone, and the hook uses
that list to drop baseline entries for files that no longer contain any
secrets. pre-commit and ``git ls-files`` pass forward slashes, so on Windows
that list never matches the baseline and those entries are never dropped. The
hook passes, the stale entries get committed, and CI on Linux -- where the
conversion changes nothing -- drops them, rewrites the baseline and fails.

This wrapper converts each argument that names an existing file the same way
detect-secrets converts the rest, then hands off to the real hook, so a commit
on Windows updates the baseline exactly as CI would.

Usage (as the pre-commit entry; pre-commit appends the staged files):
    uv run python tests/detect_secrets_hook.py --baseline .secrets.baseline
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from detect_secrets.pre_commit_hook import main as hook_main
from detect_secrets.util.path import convert_local_os_path


def native_paths(argv: Sequence[str]) -> list[str]:
    """Convert every argument that names an existing file to detect-secrets' path style.

    Options and their non-file values (such as an ``--exclude-files`` regex)
    pass through unchanged, since rewriting their slashes would change their
    meaning. So does the ``--baseline`` value: the hook checks it against
    ``git diff`` output, which always uses forward slashes.

    Args:
        argv: Hook arguments: options followed by the files to scan.

    Returns:
        The arguments, with each existing file path in the local separator style.
    """
    converted = []
    previous = ""
    for arg in argv:
        if previous != "--baseline" and os.path.isfile(arg):
            arg = convert_local_os_path(arg)
        converted.append(arg)
        previous = arg
    return converted


def main(argv: Sequence[str] | None = None) -> int:
    """Run the detect-secrets pre-commit hook on locally styled paths.

    Args:
        argv: Hook arguments; defaults to ``sys.argv[1:]``.

    Returns:
        The hook's exit code: 0 clean, 1 new secrets, 3 baseline updated.
    """
    args = sys.argv[1:] if argv is None else argv
    return hook_main(native_paths(args))


if __name__ == "__main__":
    sys.exit(main())
