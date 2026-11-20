"""Wait for every GitHub Actions job on a commit to finish, and report whether they all passed.

Run it after a push. It finds the workflow runs for the commit, follows every job in them, and
exits when all of them have finished, or when its time limit runs out.

Which commit: HEAD, unless --sha names another (anything ``git rev-parse`` understands).
Which repository: the origin remote, unless --repo OWNER/NAME names another.

How it reads GitHub:
    1. Through the gh CLI, when gh is installed and logged in. Checks every 10 seconds.
    2. Otherwise through the GitHub API, signed out. That sees public repositories only, and
       allows 60 requests an hour, so it checks every 60 seconds.
    A private repository needs gh, logged in with an account that can read it.

When it is done: every job has finished, and a second look one interval later finds nothing
new, so a run that starts late is still caught. Only jobs count; a run's own status can lag
behind its jobs. A run that finished without starting a job (a broken workflow file) counts
by its own result.

Exit codes:
    0  every job passed (skipped jobs count as passed)
    1  at least one job failed, was cancelled, or timed out
    2  could not check: no access, commit not on GitHub, rate limit, bad arguments
    3  the time limit ran out with jobs still running
    4  no workflow runs started for the commit

Output: progress goes to stderr, one line each time a job changes state. The verdict goes to
stdout: one line per job, then a line starting with RESULT.

Usage:
    uv run scripts/wait_for_ci.py [--sha SHA] [--repo OWNER/NAME] [--timeout SECONDS]
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

# Version of this helper script itself. Bump on every change so copies in other repos can be
# compared: patch = bugfix, minor = new flag/behavior, major = breaking CLI change.
__version__ = "1.0.0"

EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_ERROR = 2
EXIT_TIMED_OUT = 3
EXIT_NO_RUNS = 4
EXIT_INTERRUPTED = 130

GH_INTERVAL = 10
PUBLIC_INTERVAL = 60
DEFAULT_TIMEOUT = 540  # fits under a 10-minute command limit
APPEAR_SECONDS = 90  # how long to wait for the first run to show up
MAX_FAILED_POLLS = 3  # checks in a row that may fail to reach GitHub before giving up

API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
REQUEST_TIMEOUT = 30
GH_AUTH_REQUIRED = 4  # gh's exit code when it is not logged in
USER_AGENT = "wait-for-ci"

# A job or a run passes with one of these conclusions; any other means it did not.
PASSING = frozenset({"success", "skipped", "neutral"})
# A step with one of these conclusions is the one to look at in a job that did not pass.
FAILED_STEP = frozenset({"failure", "cancelled", "timed_out"})

_HTTP_STATUS = re.compile(r"\(HTTP (\d{3})\)")
_REPO = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
_REMOTE = re.compile(
    r"(?:https://(?:[^@/]+@)?github\.com/|ssh://git@github\.com/|git@github\.com:)"
    r"(?P<repo>[A-Za-z0-9-]+/[A-Za-z0-9._-]+?)(?:\.git)?/?"
)
_SHA = re.compile(r"[0-9a-f]{40}")


class CannotCheck(Exception):
    """The script cannot check the commit: wrong arguments, no access, or nothing to check."""


class ApiError(CannotCheck):
    """A request to GitHub failed.

    Attributes:
        status: The HTTP status, or ``None`` when GitHub gave no answer.
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        """Keep the message and the HTTP status.

        Args:
            message: What failed.
            status: The HTTP status, or ``None`` when GitHub gave no answer.
        """
        super().__init__(message)
        self.status = status

    @property
    def transient(self) -> bool:
        """Whether asking again later may work: no answer, or a server error."""
        return self.status is None or self.status >= 500


class RateLimited(ApiError):
    """GitHub refused a request because the rate limit is used up."""


class Api(Protocol):
    """Reads the GitHub REST API."""

    @property
    def name(self) -> str:
        """How the script reads GitHub, for the progress line."""
        ...

    @property
    def interval(self) -> int:
        """Seconds between checks."""
        ...

    def get(self, path: str) -> Any:
        """Return the decoded JSON body of a GET request.

        Args:
            path: The API path without a leading slash, with any query string.

        Raises:
            ApiError: The request failed.
        """
        ...


class GhApi:
    """Reads GitHub through the gh CLI, as the account gh is logged in with."""

    name = "gh"
    interval = GH_INTERVAL

    def __init__(self, gh: str) -> None:
        """Remember where gh is.

        Args:
            gh: Full path of the gh executable.
        """
        self._gh = gh

    def get(self, path: str) -> Any:
        """Return the decoded JSON body of ``gh api <path>``.

        Args:
            path: The API path without a leading slash, with any query string.

        Returns:
            The decoded body.

        Raises:
            ApiError: gh failed; status 401 when gh is not logged in.
        """
        command = [self._gh, "api", "-H", f"X-GitHub-Api-Version: {API_VERSION}", path]
        try:
            result = subprocess.run(  # noqa: S603 (gh path from shutil.which, fixed arguments)
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=REQUEST_TIMEOUT * 2,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise ApiError(f"gh api {path} did not answer in time") from error
        if result.returncode == 0:
            return json.loads(result.stdout)
        message = _first_line(result.stderr) or f"gh exited with {result.returncode}"
        if result.returncode == GH_AUTH_REQUIRED:
            raise ApiError(f"gh is not logged in: {message}", status=401)
        found = _HTTP_STATUS.search(result.stderr)
        status = int(found.group(1)) if found else None
        if status in (403, 429) and "rate limit" in result.stderr.casefold():
            raise RateLimited(f"GitHub's rate limit is used up: {message}", status=status)
        raise ApiError(f"gh api {path}: {message}", status=status)


class PublicApi:
    """Reads GitHub's API signed out: public repositories only, 60 requests an hour."""

    name = "the GitHub API (signed out)"
    interval = PUBLIC_INTERVAL

    def get(self, path: str) -> Any:
        """Return the decoded JSON body of a signed-out GET request.

        Args:
            path: The API path without a leading slash, with any query string.

        Returns:
            The decoded body.

        Raises:
            RateLimited: The signed-out rate limit is used up.
            ApiError: The request failed.
        """
        connection = http.client.HTTPSConnection(API_HOST, timeout=REQUEST_TIMEOUT)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        try:
            connection.request("GET", f"/{path}", headers=headers)
            response = connection.getresponse()
            body = response.read()
        except (OSError, http.client.HTTPException) as error:
            raise ApiError(f"GET {path}: {error}") from error
        finally:
            connection.close()
        if response.status == 200:
            return json.loads(body)
        if response.status in (403, 429) and (
            response.getheader("X-RateLimit-Remaining") == "0" or response.getheader("Retry-After")
        ):
            raise RateLimited(_rate_limit_message(response), status=response.status)
        raise ApiError(f"GET {path}: {response.status} {response.reason}", status=response.status)


def _rate_limit_message(response: http.client.HTTPResponse) -> str:
    """Say when the signed-out rate limit resets, and how to avoid it.

    Args:
        response: GitHub's refusal.

    Returns:
        The message.
    """
    reset = response.getheader("X-RateLimit-Reset")
    when = (
        datetime.fromtimestamp(int(reset), UTC).strftime(" until %H:%M UTC")
        if reset and reset.isdigit()
        else ""
    )
    return (
        f"GitHub's limit for signed-out requests is used up{when}. "
        "Install gh and log in (gh auth login) for a higher limit."
    )


def _first_line(text: str) -> str:
    """Return the first line of ``text`` that is not blank, stripped.

    Args:
        text: Any text.

    Returns:
        The line, or an empty string.
    """
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


@dataclass(frozen=True)
class Job:
    """One job of a workflow run, as GitHub last reported it.

    A run that has no jobs yet, or finished without starting one, stands in as a job of its own
    with ``job_id`` set to ``None``.
    """

    workflow: str
    name: str
    status: str
    conclusion: str | None
    url: str
    job_id: int | None
    failed_step: str | None = None

    @property
    def label(self) -> str:
        """The workflow and job names, as GitHub shows them."""
        return f"{self.workflow} / {self.name}"

    @property
    def finished(self) -> bool:
        """Whether the job has finished, whatever its result."""
        return self.status == "completed"

    @property
    def passed(self) -> bool:
        """Whether the job finished with a passing result."""
        return self.finished and self.conclusion in PASSING

    @property
    def failed(self) -> bool:
        """Whether the job finished without a passing result."""
        return self.finished and not self.passed

    @property
    def state(self) -> str:
        """The result once finished, the status until then."""
        return (self.conclusion or "no result") if self.finished else self.status


class Watcher:
    """Reads the jobs of every workflow run on one commit.

    A run is read again on every check until GitHub reports it finished with all of its jobs
    finished; from then on its jobs are remembered, which saves requests. A re-run is a new
    attempt, read afresh. Workflow names are read once each.
    """

    def __init__(self, api: Api, repo: str, sha: str) -> None:
        """Set the commit to watch.

        Args:
            api: How to read GitHub.
            repo: OWNER/NAME.
            sha: The full commit SHA.
        """
        self._api = api
        self._repo = repo
        self._sha = sha
        self._settled: dict[tuple[int, int], tuple[Job, ...]] = {}
        self._workflows: dict[int, str] = {}

    def jobs(self) -> tuple[Job, ...]:
        """Return every job on the commit, sorted by label.

        Returns:
            The jobs; empty when no run has started.

        Raises:
            ApiError: A request failed.
        """
        runs = _get_all(
            self._api, f"repos/{self._repo}/actions/runs?head_sha={self._sha}", "workflow_runs"
        )
        jobs: list[Job] = []
        for run in runs:
            key = (int(run["id"]), int(run.get("run_attempt") or 1))
            run_jobs = self._settled.get(key)
            if run_jobs is None:
                run_jobs = self._run_jobs(run)
                if run.get("status") == "completed" and all(job.finished for job in run_jobs):
                    self._settled[key] = run_jobs
            jobs.extend(run_jobs)
        return tuple(sorted(jobs, key=lambda job: (job.label, job.job_id or 0)))

    def _run_jobs(self, run: Mapping[str, Any]) -> tuple[Job, ...]:
        """Return the latest attempt's jobs of one run.

        Args:
            run: The run, as the runs list gave it.

        Returns:
            The jobs, or the run standing in as one when it has none.
        """
        workflow = self._workflow(run)
        items = _get_all(
            self._api, f"repos/{self._repo}/actions/runs/{run['id']}/jobs?filter=latest", "jobs"
        )
        if items:
            return tuple(_job(workflow, item) for item in items)
        status = str(run.get("status") or "queued")
        name = "(no jobs)" if status == "completed" else "(waiting for jobs)"
        return (
            Job(
                workflow=workflow,
                name=name,
                status=status,
                conclusion=run.get("conclusion"),
                url=str(run.get("html_url") or ""),
                job_id=None,
            ),
        )

    def _workflow(self, run: Mapping[str, Any]) -> str:
        """Return the name of the run's workflow, as its file names it.

        A run's own name is its run-name, which can carry the branch and the actor.

        Args:
            run: The run, as the runs list gave it.

        Returns:
            The workflow's name; the run's name when the run names no workflow.
        """
        workflow_id = run.get("workflow_id")
        if workflow_id is None:
            return str(run.get("name") or "workflow")
        key = int(workflow_id)
        if key not in self._workflows:
            body = self._api.get(f"repos/{self._repo}/actions/workflows/{key}")
            self._workflows[key] = str(body.get("name") or run.get("name") or "workflow")
        return self._workflows[key]


def _get_all(api: Api, path: str, key: str) -> list[dict[str, Any]]:
    """Return every item of a paged list.

    Args:
        api: How to read GitHub.
        path: The list's path, with a query string already started.
        key: The body's key that holds the items.

    Returns:
        The items of every page.

    Raises:
        ApiError: A request failed.
    """
    items: list[dict[str, Any]] = []
    page = 1
    while True:
        body = api.get(f"{path}&per_page={PAGE_SIZE}&page={page}")
        batch = list(body.get(key) or [])
        items.extend(batch)
        if len(batch) < PAGE_SIZE:
            return items
        page += 1


def _job(workflow: str, item: Mapping[str, Any]) -> Job:
    """Build a job from GitHub's description of it.

    Args:
        workflow: The workflow's name.
        item: The job, as the jobs list gave it.

    Returns:
        The job.
    """
    failed_step = next(
        (
            str(step.get("name"))
            for step in item.get("steps") or []
            if step.get("conclusion") in FAILED_STEP
        ),
        None,
    )
    return Job(
        workflow=workflow,
        name=str(item.get("name")),
        status=str(item.get("status")),
        conclusion=item.get("conclusion"),
        url=str(item.get("html_url") or ""),
        job_id=int(item["id"]),
        failed_step=failed_step,
    )


def _git(*args: str) -> str:
    """Run git in the current directory and return what it printed.

    Args:
        *args: git's arguments.

    Returns:
        The output, stripped.

    Raises:
        CannotCheck: git is missing or failed.
    """
    git = shutil.which("git")
    if git is None:
        raise CannotCheck("git is not installed")
    result = subprocess.run(  # noqa: S603 (git path from shutil.which, fixed arguments)
        [git, *args], capture_output=True, text=True, encoding="utf-8", check=False
    )
    if result.returncode != 0:
        raise CannotCheck(f"git {args[0]} failed: {_first_line(result.stderr) or 'no output'}")
    return result.stdout.strip()


def resolve_repo(repo: str | None) -> str:
    """Return the repository to check, as OWNER/NAME.

    The origin URL is never printed: it can hold a token.

    Args:
        repo: OWNER/NAME from the command line, or ``None`` for the origin remote.

    Returns:
        OWNER/NAME.

    Raises:
        CannotCheck: The name is malformed, or origin is not a github.com repository.
    """
    if repo is not None:
        if not _REPO.fullmatch(repo):
            raise CannotCheck(f"--repo must look like OWNER/NAME, not {repo!r}")
        return repo
    found = _REMOTE.fullmatch(_git("remote", "get-url", "origin"))
    if found is None:
        raise CannotCheck("the origin remote is not a github.com repository; pass --repo")
    return found.group("repo")


def resolve_sha(ref: str) -> str:
    """Return the full SHA of the commit to check.

    Args:
        ref: A full SHA, or anything ``git rev-parse`` understands.

    Returns:
        The full SHA.

    Raises:
        CannotCheck: The ref names no commit here.
    """
    if _SHA.fullmatch(ref.casefold()):
        return ref.casefold()
    try:
        return _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except CannotCheck as error:
        raise CannotCheck(f"{ref!r} is not a commit in this repository") from error


def choose_api(repo: str) -> Api:
    """Pick how to read GitHub: gh when it is installed and logged in, else signed out.

    Args:
        repo: OWNER/NAME.

    Returns:
        An API that can read the repository.

    Raises:
        CannotCheck: Neither way can read the repository.
    """
    gh = shutil.which("gh")
    if gh is None:
        print("gh is not installed; reading GitHub signed out.", file=sys.stderr)
    else:
        api = GhApi(gh)
        try:
            api.get(f"repos/{repo}")
        except ApiError as error:
            if error.status != 401:
                if error.status == 404:
                    raise CannotCheck(
                        f"gh is logged in, but cannot see {repo}. "
                        "Log in with an account that can read it: gh auth login"
                    ) from error
                raise
            print("gh is not logged in; reading GitHub signed out.", file=sys.stderr)
        else:
            return api
    public = PublicApi()
    try:
        public.get(f"repos/{repo}")
    except ApiError as error:
        if error.status == 404:
            raise CannotCheck(
                f"{repo} is private or does not exist. "
                "Install gh and log in with an account that can read it: gh auth login"
            ) from error
        raise
    return public


def check_commit(api: Api, repo: str, sha: str) -> None:
    """Make sure GitHub has the commit; no run will ever start for one it does not have.

    Args:
        api: How to read GitHub.
        repo: OWNER/NAME.
        sha: The full commit SHA.

    Raises:
        CannotCheck: GitHub does not have the commit.
    """
    try:
        api.get(f"repos/{repo}/commits/{sha}")
    except ApiError as error:
        if error.status in (404, 422):
            raise CannotCheck(
                f"GitHub does not have commit {sha[:7]} in {repo}. Push it."
            ) from error
        raise


def watch(
    api: Api,
    sha: str,
    watcher: Watcher,
    timeout: int,
    *,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Check the jobs until they are all finished or time runs out, then print the verdict.

    Args:
        api: How to read GitHub; sets the time between checks.
        sha: The full commit SHA, for the messages.
        watcher: Reads the jobs.
        timeout: Seconds before giving up on jobs still running.
        clock: Seconds from a fixed point, for measuring time.
        sleep: Waits the given seconds.

    Returns:
        The exit code.

    Raises:
        ApiError: GitHub refused a request, or could not be reached several times in a row.
    """
    start = clock()
    previous: tuple[Job, ...] | None = None
    shown: dict[tuple[str, int | None], str] = {}
    failed_polls = 0
    while True:
        try:
            current = watcher.jobs()
        except ApiError as error:
            failed_polls += 1
            if not error.transient or failed_polls >= MAX_FAILED_POLLS:
                raise
            print(f"Could not reach GitHub ({error}); trying again.", file=sys.stderr)
        else:
            failed_polls = 0
            _show_changes(current, shown)
            elapsed = clock() - start
            if not current and elapsed >= min(APPEAR_SECONDS, timeout):
                return _no_runs(sha, elapsed)
            if current and all(job.finished for job in current) and current == previous:
                return report(current, timeout)
            previous = current
        left = start + timeout - clock()
        if left <= 0:
            return report(previous, timeout) if previous else _no_runs(sha, timeout)
        sleep(min(api.interval, left))


def _no_runs(sha: str, seconds: float) -> int:
    """Print the RESULT line for a commit no run started for, and return the exit code.

    Args:
        sha: The full commit SHA.
        seconds: How long the script waited.

    Returns:
        ``EXIT_NO_RUNS``.
    """
    print(f"RESULT: NO RUNS - no workflow run started for {sha[:7]} in {seconds:.0f} s.")
    return EXIT_NO_RUNS


def _show_changes(jobs: Sequence[Job], shown: dict[tuple[str, int | None], str]) -> None:
    """Print a progress line for each job whose state changed since the last check.

    Args:
        jobs: The jobs now.
        shown: The state last printed for each job; updated.
    """
    for job in jobs:
        key = (job.label, job.job_id)
        if shown.get(key) != job.state:
            shown[key] = job.state
            print(f"  {job.state:<12} {job.label}", file=sys.stderr)


def report(jobs: Sequence[Job], timeout: int) -> int:
    """Print one line per job and the RESULT line, and return the exit code.

    Args:
        jobs: Every job on the commit.
        timeout: The time limit, for the message when jobs are still running.

    Returns:
        ``EXIT_FAILED`` when any job failed, else ``EXIT_TIMED_OUT`` when any is still running,
        else ``EXIT_PASSED``.
    """
    for job in jobs:
        if job.failed:
            step = f', at step "{job.failed_step}"' if job.failed_step else ""
            print(f"FAIL  {job.label} ({job.state}{step})")
            print(f"      {job.url}")
            if job.job_id is not None:
                print(f"      logs: gh run view --job {job.job_id} --log-failed")
        elif not job.finished:
            print(f"WAIT  {job.label} ({job.state})")
        elif job.conclusion == "skipped":
            print(f"SKIP  {job.label}")
        else:
            print(f"PASS  {job.label}")
    failed = sum(job.failed for job in jobs)
    running = sum(not job.finished for job in jobs)
    skipped = sum(job.finished and job.conclusion == "skipped" for job in jobs)
    if failed:
        still = f" {running} still running after {timeout} s." if running else ""
        print(f"RESULT: FAILED - {failed} of {len(jobs)} jobs failed.{still}")
        return EXIT_FAILED
    if running:
        print(f"RESULT: TIMED OUT - {running} of {len(jobs)} jobs still running after {timeout} s.")
        return EXIT_TIMED_OUT
    skips = f", {skipped} skipped" if skipped else ""
    print(f"RESULT: PASSED - {len(jobs) - skipped} jobs passed{skips}.")
    return EXIT_PASSED


def _positive(text: str) -> int:
    """Read a whole number of seconds, at least 1.

    Args:
        text: The command-line value.

    Returns:
        The number.

    Raises:
        argparse.ArgumentTypeError: It is not a whole number of at least 1.
    """
    if not text.isdigit() or int(text) < 1:
        raise argparse.ArgumentTypeError(f"must be a whole number of seconds, at least 1: {text!r}")
    return int(text)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Read the command line.

    Args:
        argv: Arguments without the program name. Defaults to ``sys.argv[1:]``.

    Returns:
        The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--sha", default="HEAD", help="commit to check (default: HEAD)")
    parser.add_argument("--repo", help="OWNER/NAME on github.com (default: the origin remote)")
    parser.add_argument(
        "--timeout",
        type=_positive,
        default=DEFAULT_TIMEOUT,
        help=f"seconds to wait for jobs to finish (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
    *,
    api: Api | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Wait for the commit's jobs and print the verdict.

    Args:
        argv: Arguments without the program name. Defaults to ``sys.argv[1:]``.
        api: How to read GitHub. Defaults to gh when it is logged in, else signed out.
        clock: Seconds from a fixed point, for measuring time.
        sleep: Waits the given seconds.

    Returns:
        The exit code; see the module docstring.
    """
    args = parse_args(argv)
    try:
        repo = resolve_repo(args.repo)
        sha = resolve_sha(args.sha)
        if api is None:
            api = choose_api(repo)
        check_commit(api, repo, sha)
        print(
            f"Waiting for GitHub Actions on {sha[:7]} in {repo}, through {api.name}, "
            f"checking every {api.interval} s for up to {args.timeout} s.",
            file=sys.stderr,
        )
        return watch(api, sha, Watcher(api, repo, sha), args.timeout, clock=clock, sleep=sleep)
    except CannotCheck as error:
        print(f"RESULT: COULD NOT CHECK - {error}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("RESULT: STOPPED - interrupted.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
