"""Shared helpers for the interactive repo helper scripts in this folder.

Python counterparts of the helper functions the original PowerShell scripts
duplicated (Write-Section, Write-Info, Write-Run, Confirm-Step, Invoke-Step,
Invoke-Native). Standard library only, so the scripts run with a bare
``python`` or ``uv run`` before any dependencies are installed.

House style for the scripts that use this module:
  - Interactive: every state-changing step is confirmed with a y/n prompt.
  - Transparent: every git/uv/gh command is echoed before it runs, and its
    output streams to the terminal rather than being captured and hidden.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence
from typing import NoReturn


def _enable_windows_ansi() -> None:
    """Turn on ANSI escape processing in the legacy Windows console.

    Windows Terminal and VS Code handle ANSI already; this is a no-op there.
    """
    if sys.platform != "win32":  # also narrows ctypes.windll for type checkers
        return
    import ctypes

    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except (OSError, AttributeError):  # fmt: skip
        pass


def _supports_color() -> bool:
    """Decide whether to emit ANSI colors, enabling VT processing on Windows."""
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        _enable_windows_ansi()
    return True


_COLOR = _supports_color()

_assume_yes = False


def set_assume_yes(value: bool) -> None:
    """Answer every confirmation prompt with 'y' (for a script's -y/--yes flag).

    Args:
        value: ``True`` to auto-answer prompts, ``False`` to ask normally.
    """
    global _assume_yes
    _assume_yes = value


def _code(escape: str) -> str:
    return escape if _COLOR else ""


CYAN = _code("\x1b[36m")
GREEN = _code("\x1b[32m")
YELLOW = _code("\x1b[33m")
RED = _code("\x1b[31m")
GRAY = _code("\x1b[90m")
RESET = _code("\x1b[0m")


def section(title: str) -> None:
    """Print a labelled section header to separate steps in the output.

    Args:
        title: Section title.
    """
    print()
    print(f"{CYAN}== {title} =={RESET}", flush=True)


def info(label: str, value: str) -> None:
    """Print an aligned ``label: value`` line.

    Args:
        label: Short field name.
        value: Field value.
    """
    print(f"  {GRAY}{label + ':':<20}{RESET}{value}")


def echo(command_text: str) -> None:
    """Show a command line just before it runs.

    Args:
        command_text: The command as it would be typed in a shell.
    """
    # Flush so the echo lands before the command's own output when stdout is
    # piped (block-buffered) rather than a console.
    print(f"  {GRAY}> {command_text}{RESET}", flush=True)


def warn(message: str) -> None:
    """Print a yellow warning line.

    Args:
        message: Warning text.
    """
    print(f"{YELLOW}{message}{RESET}")


def success(message: str) -> None:
    """Print a green success line.

    Args:
        message: Success text.
    """
    print(f"{GREEN}{message}{RESET}")


def die(message: str) -> NoReturn:
    """Print an error and exit with status 1.

    Args:
        message: Error text.
    """
    print(f"{RED}ERROR: {message}{RESET}", file=sys.stderr)
    sys.exit(1)


def confirm(prompt: str) -> bool:
    """Ask the user a yes/no question on the terminal.

    Args:
        prompt: Question to display (without the ``[y/n]`` suffix).

    Returns:
        ``True`` for yes, ``False`` for no. Always ``True`` in assume-yes mode,
        with the auto-answer printed so the transcript still shows the step.
    """
    if _assume_yes:
        print(f"{prompt} [y/n] y {GRAY}(auto: --yes){RESET}")
        return True
    while True:
        answer = input(f"{prompt} [y/n] ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer 'y' or 'n'.")


def prompt_value(prompt: str, *, default: str = "") -> str:
    """Prompt for a single line of input with an optional default.

    Args:
        prompt: Text to display before the input cursor.
        default: Value returned when the user presses Enter without typing.

    Returns:
        The entered value, or ``default`` if nothing was entered. In assume-yes
        mode the default is returned without prompting.
    """
    suffix = f" [{default}]" if default else ""
    if _assume_yes:
        print(f"{prompt}{suffix}: {default} {GRAY}(auto: --yes){RESET}")
        return default
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def step(prompt: str) -> None:
    """Confirm a step before it runs; answering 'n' aborts the whole script.

    Earlier steps are not undone, so the abort message reports where the
    repository was left.

    Args:
        prompt: Description of the action about to be taken.
    """
    if confirm(prompt):
        return
    print()
    warn("Aborted by user.")
    branch = capture_ok(["git", "branch", "--show-current"]) or "(unknown)"
    warn(f"Repository is currently on branch '{branch}'.")
    warn("Any steps already completed above have NOT been undone.")
    sys.exit(1)


def run(args: Sequence[str], *, cwd: str | os.PathLike[str] | None = None) -> None:
    """Echo a command, run it with output streaming to the terminal, and stop on failure.

    Args:
        args: Command and arguments.
        cwd: Working directory for the command, if not the current one.
    """
    echo(subprocess.list2cmdline(args))
    result = subprocess.run(list(args), cwd=cwd)  # noqa: S603  (fixed argv list, no shell)
    if result.returncode != 0:
        die(f"{subprocess.list2cmdline(args)} failed (exit {result.returncode})")


def run_ok(args: Sequence[str], *, cwd: str | os.PathLike[str] | None = None) -> int:
    """Echo a command, stream its output, and return its exit code without exiting.

    Like :func:`run`, but lets the caller decide what to do on a non-zero exit
    (e.g. a ``git push`` that origin may reject) instead of stopping the script.
    Output still streams to the terminal, keeping the house transparency rule.

    Args:
        args: Command and arguments.
        cwd: Working directory for the command, if not the current one.

    Returns:
        The command's exit code.
    """
    echo(subprocess.list2cmdline(args))
    result = subprocess.run(list(args), cwd=cwd)  # noqa: S603  (fixed argv list, no shell)
    return result.returncode


def exit_code(args: Sequence[str], *, cwd: str | os.PathLike[str] | None = None) -> int:
    """Run a command quietly and return its exit code.

    For commands used as yes/no probes (e.g. ``git diff-index --quiet``).

    Args:
        args: Command and arguments.
        cwd: Working directory for the command, if not the current one.

    Returns:
        The command's exit code.
    """
    result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
        list(args),
        cwd=cwd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode


def capture(
    args: Sequence[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
    quiet_stderr: bool = False,
    echo_cmd: bool = False,
) -> str:
    """Run a command and return its stdout, stopping the script on failure.

    stderr still streams to the terminal unless ``quiet_stderr`` is set.

    Args:
        args: Command and arguments.
        cwd: Working directory for the command, if not the current one.
        quiet_stderr: Suppress stderr (for commands whose failure is handled
            with a clearer message).
        echo_cmd: Show the command line before running it.

    Returns:
        The command's stdout, stripped.
    """
    if echo_cmd:
        echo(subprocess.list2cmdline(args))
    result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
        list(args),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL if quiet_stderr else None,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        die(f"{subprocess.list2cmdline(args)} failed (exit {result.returncode})")
    return (result.stdout or "").strip()


def capture_ok(args: Sequence[str], *, cwd: str | os.PathLike[str] | None = None) -> str | None:
    """Run a command quietly and return its stdout, or ``None`` if it failed.

    For probing commands where a non-zero exit is an expected answer (e.g.
    ``git symbolic-ref`` on a detached HEAD, ``gh pr view`` with no PR).

    Args:
        args: Command and arguments.
        cwd: Working directory for the command, if not the current one.

    Returns:
        The command's stdout (stripped), or ``None`` on non-zero exit.
    """
    result = subprocess.run(  # noqa: S603  (fixed argv list, no shell)
        list(args),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip()


# Plain Git Bash (mintty) relays a native Windows program's stdin through a
# pipe, and interactive reads are known to stall mid-session — winpty exists
# for exactly this. Warn up front instead of letting a y/n prompt freeze the
# terminal. VS Code's integrated terminal sets TERM_PROGRAM=vscode and is fine.
if os.environ.get("TERM_PROGRAM") == "mintty":
    warn("WARNING: interactive prompts can freeze in plain Git Bash (mintty).")
    warn("Run via 'winpty python ...', or use PowerShell or VS Code's terminal.")
