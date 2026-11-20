"""Unit tests for scripts/wait_for_ci.py.

GitHub is replaced by a fake that serves runs and jobs from a list of states, one state per
check, and time by a fake clock that the script's sleeps move forward. Nothing reaches GitHub.
"""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs

import pytest

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
REPO = "owner/repo"
SHA = "0123456789abcdef0123456789abcdef01234567"

# One state: the runs on the commit, and each run's jobs by run id.
State = tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]
# The workflows the fake knows, by id.
WORKFLOWS = {100: "CI", 200: "Audit"}


@pytest.fixture
def ci(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The script as a module."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    return importlib.import_module("wait_for_ci")


def a_run(
    run_id: int,
    status: str = "completed",
    conclusion: str | None = "success",
    name: str = "CI",
    attempt: int = 1,
) -> dict[str, Any]:
    """A run of the named workflow; like GitHub's, its own name is a run-name."""
    workflow_id = next(key for key, value in WORKFLOWS.items() if value == name)
    return {
        "id": run_id,
        "name": f"{name} on develop push by @someone",
        "workflow_id": workflow_id,
        "status": status,
        "conclusion": conclusion,
        "run_attempt": attempt,
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
    }


def a_job(
    job_id: int,
    name: str,
    status: str = "completed",
    conclusion: str | None = "success",
    steps: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return {
        "id": job_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "html_url": f"https://github.com/{REPO}/actions/runs/1/job/{job_id}",
        "steps": list(steps),
    }


class FakeApi:
    """Serves one state per check; a sleep moves on to the next state, the last one stays."""

    name = "the fake API"
    interval = 10

    def __init__(self, ci: ModuleType, states: list[State]) -> None:
        self.ci = ci
        self.states = states
        self.calls: list[str] = []
        self.errors: list[BaseException | None] = []  # raised one per runs-list request

    def advance(self) -> None:
        if len(self.states) > 1:
            self.states.pop(0)

    def get(self, path: str) -> Any:
        self.calls.append(path)
        runs, jobs = self.states[0]
        base, _, query = path.partition("?")
        page = int(parse_qs(query).get("page", ["1"])[0])
        if base == f"repos/{REPO}/actions/runs":
            if self.errors:
                error = self.errors.pop(0)
                if error is not None:
                    raise error
            return {"workflow_runs": runs if page == 1 else []}
        if base.startswith(f"repos/{REPO}/actions/runs/") and base.endswith("/jobs"):
            run_id = int(base.split("/")[-2])
            size = self.ci.PAGE_SIZE
            return {"jobs": jobs.get(run_id, [])[(page - 1) * size : page * size]}
        if base.startswith(f"repos/{REPO}/actions/workflows/"):
            return {"name": WORKFLOWS[int(base.split("/")[-1])]}
        if base == f"repos/{REPO}/commits/{SHA}":
            return {"sha": SHA}
        raise AssertionError(f"unexpected path {path}")

    def jobs_calls(self, run_id: int) -> int:
        return sum(f"/runs/{run_id}/jobs" in call for call in self.calls)

    def workflow_calls(self) -> int:
        return sum("/actions/workflows/" in call for call in self.calls)


class Clock:
    """Fake time: each sleep moves the clock and the fake API on."""

    def __init__(self, api: FakeApi) -> None:
        self.now = 0.0
        self.api = api
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds
        self.api.advance()


def watch(ci: ModuleType, api: FakeApi, timeout: int = 540) -> int:
    clock = Clock(api)
    result: int = ci.watch(
        api, SHA, ci.Watcher(api, REPO, SHA), timeout, clock=clock, sleep=clock.sleep
    )
    return result


def result_line(capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    out, err = capsys.readouterr()
    return out.strip().splitlines()[-1], out + err


# --- the verdict -------------------------------------------------------------------------------


def test_jobs_that_pass_exit_0_after_a_second_look(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    running: State = (
        [a_run(1, "in_progress", None)],
        {1: [a_job(11, "lint", "in_progress", None), a_job(12, "test", "queued", None)]},
    )
    done: State = ([a_run(1)], {1: [a_job(11, "lint"), a_job(12, "test")]})
    api = FakeApi(ci, [running, done])

    assert watch(ci, api) == ci.EXIT_PASSED
    last, text = result_line(capsys)
    assert last == "RESULT: PASSED - 2 jobs passed."
    assert "PASS  CI / lint" in text
    assert "PASS  CI / test" in text
    assert "  in_progress  CI / lint" in text  # progress, once per change
    assert text.count("success      CI / lint") == 1


def test_a_failed_job_exits_1_with_its_step_and_where_to_read_the_log(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    steps = ({"name": "Set up", "conclusion": "success"}, {"name": "Test", "conclusion": "failure"})
    done: State = (
        [a_run(1, conclusion="failure")],
        {1: [a_job(11, "lint"), a_job(12, "test", conclusion="failure", steps=steps)]},
    )
    api = FakeApi(ci, [done])

    assert watch(ci, api) == ci.EXIT_FAILED
    last, text = result_line(capsys)
    assert last == "RESULT: FAILED - 1 of 2 jobs failed."
    assert 'FAIL  CI / test (failure, at step "Test")' in text
    assert f"https://github.com/{REPO}/actions/runs/1/job/12" in text
    assert "logs: gh run view --job 12 --log-failed" in text


def test_a_cancelled_job_is_a_failure(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test", conclusion="cancelled")]})])

    assert watch(ci, api) == ci.EXIT_FAILED
    assert "FAIL  CI / test (cancelled)" in capsys.readouterr().out


def test_skipped_jobs_count_as_passed(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    api = FakeApi(
        ci, [([a_run(1)], {1: [a_job(11, "test"), a_job(12, "deploy", conclusion="skipped")]})]
    )

    assert watch(ci, api) == ci.EXIT_PASSED
    last, text = result_line(capsys)
    assert last == "RESULT: PASSED - 1 jobs passed, 1 skipped."
    assert "SKIP  CI / deploy" in text


def test_a_run_that_starts_late_is_still_caught(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    ci_done = a_run(1)
    early: State = ([ci_done], {1: [a_job(11, "test")]})
    late: State = (
        [ci_done, a_run(2, "queued", None, name="Audit")],
        {1: [a_job(11, "test")], 2: [a_job(21, "audit", "queued", None)]},
    )
    failed: State = (
        [ci_done, a_run(2, conclusion="failure", name="Audit")],
        {1: [a_job(11, "test")], 2: [a_job(21, "audit", conclusion="failure")]},
    )
    api = FakeApi(ci, [early, late, failed])

    assert watch(ci, api) == ci.EXIT_FAILED
    assert "FAIL  Audit / audit" in capsys.readouterr().out


def test_a_run_without_jobs_yet_keeps_the_wait_going(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    waiting: State = ([a_run(1, "queued", None)], {})
    done: State = ([a_run(1)], {1: [a_job(11, "test")]})
    api = FakeApi(ci, [waiting, waiting, done])

    assert watch(ci, api) == ci.EXIT_PASSED
    assert "queued       CI / (waiting for jobs)" in capsys.readouterr().err


def test_a_run_that_finished_without_jobs_counts_by_its_own_result(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeApi(ci, [([a_run(1, conclusion="startup_failure")], {})])

    assert watch(ci, api) == ci.EXIT_FAILED
    out = capsys.readouterr().out
    assert "FAIL  CI / (no jobs) (startup_failure)" in out
    assert "gh run view" not in out


def test_a_rerun_is_read_afresh(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    first: State = (
        [a_run(1, conclusion="failure")],
        {1: [a_job(11, "test", conclusion="failure")]},
    )
    rerun: State = (
        [a_run(1, "in_progress", None, attempt=2)],
        {1: [a_job(12, "test", "in_progress", None)]},
    )
    passed: State = ([a_run(1, attempt=2)], {1: [a_job(12, "test")]})
    api = FakeApi(ci, [first, rerun, passed])

    assert watch(ci, api) == ci.EXIT_PASSED


def test_a_finished_run_is_not_read_again(ci: ModuleType) -> None:
    ci_done = a_run(1)
    running: State = (
        [ci_done, a_run(2, "in_progress", None, name="Audit")],
        {1: [a_job(11, "test")], 2: [a_job(21, "audit", "in_progress", None)]},
    )
    done: State = (
        [ci_done, a_run(2, name="Audit")],
        {1: [a_job(11, "test")], 2: [a_job(21, "audit")]},
    )
    api = FakeApi(ci, [running, running, done])

    assert watch(ci, api) == ci.EXIT_PASSED
    assert api.jobs_calls(1) == 1
    assert api.jobs_calls(2) == 3


def test_a_run_reported_unfinished_is_read_again_though_its_jobs_are_done(ci: ModuleType) -> None:
    lagging: State = ([a_run(1, "in_progress", None)], {1: [a_job(11, "test")]})
    api = FakeApi(ci, [lagging])

    assert watch(ci, api) == ci.EXIT_PASSED
    assert api.jobs_calls(1) == 2


def test_every_page_of_jobs_is_read(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    many = [a_job(1000 + n, f"shard {n:03}") for n in range(150)]
    api = FakeApi(ci, [([a_run(1)], {1: many})])

    assert watch(ci, api) == ci.EXIT_PASSED
    assert result_line(capsys)[0] == "RESULT: PASSED - 150 jobs passed."


def test_jobs_are_labelled_by_workflow_name_read_once(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    running: State = ([a_run(1, "in_progress", None)], {1: [a_job(11, "t", "in_progress", None)]})
    done: State = ([a_run(1)], {1: [a_job(11, "t")]})
    api = FakeApi(ci, [running, running, done])

    assert watch(ci, api) == ci.EXIT_PASSED
    out = capsys.readouterr().out
    assert "PASS  CI / t\n" in out
    assert "on develop push" not in out
    assert api.workflow_calls() == 1


def test_a_run_naming_no_workflow_is_labelled_by_its_own_name(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    run = a_run(1)
    del run["workflow_id"]
    api = FakeApi(ci, [([run], {1: [a_job(11, "t")]})])

    assert watch(ci, api) == ci.EXIT_PASSED
    assert "PASS  CI on develop push by @someone / t" in capsys.readouterr().out
    assert api.workflow_calls() == 0


# --- waiting, time limits, and errors -----------------------------------------------------------


def test_no_runs_exits_4_after_the_appear_window(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeApi(ci, [([], {})])

    assert watch(ci, api) == ci.EXIT_NO_RUNS
    assert result_line(capsys)[0] == (
        f"RESULT: NO RUNS - no workflow run started for {SHA[:7]} in {ci.APPEAR_SECONDS} s."
    )


def test_no_runs_within_a_short_time_limit_exits_4(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeApi(ci, [([], {})])

    assert watch(ci, api, timeout=25) == ci.EXIT_NO_RUNS
    assert result_line(capsys)[0].endswith(" in 25 s.")


def test_jobs_still_running_at_the_time_limit_exit_3(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    running: State = (
        [a_run(1, "in_progress", None)],
        {1: [a_job(11, "lint"), a_job(12, "test", "in_progress", None)]},
    )
    api = FakeApi(ci, [running])
    clock = Clock(api)

    code = ci.watch(api, SHA, ci.Watcher(api, REPO, SHA), 25, clock=clock, sleep=clock.sleep)

    assert code == ci.EXIT_TIMED_OUT
    assert clock.sleeps == [10, 10, 5]  # the last check falls on the time limit
    last, text = result_line(capsys)
    assert last == "RESULT: TIMED OUT - 1 of 2 jobs still running after 25 s."
    assert "WAIT  CI / test (in_progress)" in text


def test_jobs_finished_on_the_last_check_are_reported_as_they_are(ci: ModuleType) -> None:
    running: State = ([a_run(1, "in_progress", None)], {1: [a_job(11, "t", "in_progress", None)]})
    done: State = ([a_run(1)], {1: [a_job(11, "t")]})
    api = FakeApi(ci, [running, done])

    assert watch(ci, api, timeout=10) == ci.EXIT_PASSED


def test_a_failure_outranks_jobs_still_running(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    mixed: State = (
        [a_run(1, "in_progress", None)],
        {1: [a_job(11, "lint", conclusion="failure"), a_job(12, "test", "in_progress", None)]},
    )
    api = FakeApi(ci, [mixed])

    assert watch(ci, api, timeout=20) == ci.EXIT_FAILED
    assert result_line(capsys)[0] == (
        "RESULT: FAILED - 1 of 2 jobs failed. 1 still running after 20 s."
    )


def test_github_out_of_reach_is_tried_again(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test")]})])
    api.errors = [ci.ApiError("no answer"), None, ci.ApiError("bad gateway", status=502)]

    assert watch(ci, api) == ci.EXIT_PASSED
    assert "Could not reach GitHub (no answer); trying again." in capsys.readouterr().err


def test_github_out_of_reach_too_often_gives_up(ci: ModuleType) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test")]})])
    api.errors = [ci.ApiError("no answer")] * ci.MAX_FAILED_POLLS

    with pytest.raises(ci.ApiError, match="no answer"):
        watch(ci, api)


def test_a_refusal_is_not_tried_again(ci: ModuleType) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test")]})])
    api.errors = [ci.RateLimited("used up", status=403)]

    with pytest.raises(ci.RateLimited):
        watch(ci, api)
    assert len(api.calls) == 1


# --- which repository and commit ----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo",
        "https://github.com/owner/repo/",
        "https://x-access-token:abc@github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "ssh://git@github.com/owner/repo.git",
    ],
)
def test_the_repository_comes_from_origin(
    ci: ModuleType, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setattr(ci, "_git", lambda *args: url)

    assert ci.resolve_repo(None) == REPO


def test_an_origin_off_github_is_refused_without_showing_the_url(
    ci: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ci, "_git", lambda *args: "https://user:token@gitlab.com/owner/repo.git")

    with pytest.raises(ci.CannotCheck) as caught:
        ci.resolve_repo(None)
    assert "token" not in str(caught.value)
    assert "pass --repo" in str(caught.value)


def test_repo_on_the_command_line_must_be_owner_slash_name(ci: ModuleType) -> None:
    assert ci.resolve_repo("Owner-1/repo.name_2") == "Owner-1/repo.name_2"
    with pytest.raises(ci.CannotCheck, match="OWNER/NAME"):
        ci.resolve_repo("owner/repo/extra")


def test_a_full_sha_needs_no_git(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_git(*args: str) -> str:
        raise AssertionError("git was run")

    monkeypatch.setattr(ci, "_git", no_git)

    assert ci.resolve_sha(SHA.upper()) == SHA


def test_a_ref_is_resolved_by_git(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        asked.append(args)
        return SHA

    monkeypatch.setattr(ci, "_git", git)

    assert ci.resolve_sha("HEAD") == SHA
    assert asked == [("rev-parse", "--verify", "--quiet", "HEAD^{commit}")]


def test_a_ref_git_does_not_know_is_refused(ci: ModuleType) -> None:
    with pytest.raises(ci.CannotCheck, match="'no-such-ref' is not a commit"):
        ci.resolve_sha("no-such-ref")


def test_git_runs_and_reports_failure(ci: ModuleType) -> None:
    assert ci._git("--version").startswith("git version")
    with pytest.raises(ci.CannotCheck, match="git rev-parse failed"):
        ci._git("rev-parse", "--verify", "no-such-ref^{commit}")


def test_git_missing_is_reported(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ci.shutil, "which", lambda name: None)

    with pytest.raises(ci.CannotCheck, match="git is not installed"):
        ci._git("--version")


# --- choosing gh or the signed-out API ----------------------------------------------------------


@pytest.fixture
def probes(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Make gh's and the signed-out API's probe of the repository answer as a test sets."""
    answers: dict[str, Any] = {"gh_path": "/bin/gh", "gh": None, "public": None}

    def which(name: str) -> str | None:
        return answers["gh_path"] if name == "gh" else None

    def answer(key: str) -> Any:
        def get(self: object, path: str) -> Any:
            assert path == f"repos/{REPO}"
            if answers[key] is not None:
                raise answers[key]
            return {"full_name": REPO}

        return get

    monkeypatch.setattr(ci.shutil, "which", which)
    monkeypatch.setattr(ci.GhApi, "get", answer("gh"))
    monkeypatch.setattr(ci.PublicApi, "get", answer("public"))
    return answers


def test_gh_is_used_when_it_can_read_the_repository(ci: ModuleType, probes: dict[str, Any]) -> None:
    api = ci.choose_api(REPO)

    assert isinstance(api, ci.GhApi)
    assert api.interval == 10


def test_without_gh_the_api_is_read_signed_out(
    ci: ModuleType, probes: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    probes["gh_path"] = None

    api = ci.choose_api(REPO)

    assert isinstance(api, ci.PublicApi)
    assert api.interval == 60
    assert "gh is not installed" in capsys.readouterr().err


def test_gh_not_logged_in_falls_back_to_signed_out(
    ci: ModuleType, probes: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    probes["gh"] = ci.ApiError("not logged in", status=401)

    assert isinstance(ci.choose_api(REPO), ci.PublicApi)
    assert "gh is not logged in" in capsys.readouterr().err


def test_gh_without_access_is_an_error(ci: ModuleType, probes: dict[str, Any]) -> None:
    probes["gh"] = ci.ApiError("Not Found", status=404)

    with pytest.raises(ci.CannotCheck, match="gh is logged in, but cannot see owner/repo"):
        ci.choose_api(REPO)


def test_gh_failing_otherwise_is_an_error(ci: ModuleType, probes: dict[str, Any]) -> None:
    probes["gh"] = ci.ApiError("no answer")

    with pytest.raises(ci.ApiError, match="no answer"):
        ci.choose_api(REPO)


def test_a_private_repository_without_gh_is_an_error(
    ci: ModuleType, probes: dict[str, Any]
) -> None:
    probes["gh_path"] = None
    probes["public"] = ci.ApiError("Not Found", status=404)

    with pytest.raises(ci.CannotCheck, match=r"private or does not exist\..*gh auth login"):
        ci.choose_api(REPO)


def test_the_signed_out_api_failing_otherwise_is_an_error(
    ci: ModuleType, probes: dict[str, Any]
) -> None:
    probes["gh_path"] = None
    probes["public"] = ci.RateLimited("used up", status=403)

    with pytest.raises(ci.RateLimited):
        ci.choose_api(REPO)


@pytest.mark.parametrize("status", [404, 422])
def test_a_commit_github_lacks_is_an_error(ci: ModuleType, status: int) -> None:
    class Missing:
        def get(self, path: str) -> Any:
            raise ci.ApiError("missing", status=status)

    with pytest.raises(ci.CannotCheck, match=r"does not have commit 0123456 in owner/repo\. Push"):
        ci.check_commit(Missing(), REPO, SHA)


def test_a_commit_check_failing_otherwise_is_passed_on(ci: ModuleType) -> None:
    class Broken:
        def get(self, path: str) -> Any:
            raise ci.ApiError("server error", status=500)

    with pytest.raises(ci.ApiError, match="server error"):
        ci.check_commit(Broken(), REPO, SHA)


# --- gh ---------------------------------------------------------------------------------------


def gh_answers(
    ci: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int, out: str = "", err: str = ""
) -> list[list[str]]:
    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, code, out, err)

    monkeypatch.setattr(ci.subprocess, "run", run)
    return commands


def test_gh_api_returns_the_body(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = gh_answers(ci, monkeypatch, 0, out='{"full_name": "owner/repo"}')

    assert ci.GhApi("gh").get(f"repos/{REPO}") == {"full_name": REPO}
    assert commands == [["gh", "api", "-H", "X-GitHub-Api-Version: 2022-11-28", f"repos/{REPO}"]]


def test_gh_not_logged_in_is_status_401(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    gh_answers(ci, monkeypatch, 4, err="To get started with GitHub CLI, please run: gh auth login")

    with pytest.raises(ci.ApiError) as caught:
        ci.GhApi("gh").get(f"repos/{REPO}")
    assert caught.value.status == 401


def test_gh_http_errors_carry_the_status(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    gh_answers(ci, monkeypatch, 1, out='{"message": "Not Found"}', err="gh: Not Found (HTTP 404)\n")

    with pytest.raises(ci.ApiError, match="Not Found") as caught:
        ci.GhApi("gh").get(f"repos/{REPO}")
    assert caught.value.status == 404
    assert not caught.value.transient


def test_gh_rate_limit_is_rate_limited(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    gh_answers(ci, monkeypatch, 1, err="gh: API rate limit exceeded for user (HTTP 403)")

    with pytest.raises(ci.RateLimited):
        ci.GhApi("gh").get(f"repos/{REPO}")


def test_gh_failing_without_a_status_is_transient(
    ci: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    gh_answers(ci, monkeypatch, 1)

    with pytest.raises(ci.ApiError, match="gh exited with 1") as caught:
        ci.GhApi("gh").get(f"repos/{REPO}")
    assert caught.value.transient


def test_gh_hanging_is_transient(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    def hang(command: list[str], **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(ci.subprocess, "run", hang)

    with pytest.raises(ci.ApiError, match="did not answer in time") as caught:
        ci.GhApi("gh").get(f"repos/{REPO}")
    assert caught.value.transient


# --- the signed-out API ------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int, body: bytes, headers: dict[str, str]) -> None:
        self.status = status
        self.reason = {200: "OK", 403: "Forbidden", 404: "Not Found", 429: "Too Many"}[status]
        self.body = body
        self.headers = headers

    def read(self) -> bytes:
        return self.body

    def getheader(self, name: str) -> str | None:
        return self.headers.get(name)


@pytest.fixture
def https(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Replace the HTTPS connection; a test sets the response and reads what was sent."""
    seen: dict[str, Any] = {"response": FakeResponse(200, b"{}", {}), "error": None}

    class Connection:
        def __init__(self, host: str, timeout: int) -> None:
            seen["host"] = host
            seen["timeout"] = timeout

        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            if seen["error"] is not None:
                raise seen["error"]
            seen["request"] = (method, path, headers)

        def getresponse(self) -> FakeResponse:
            response: FakeResponse = seen["response"]
            return response

        def close(self) -> None:
            seen["closed"] = True

    monkeypatch.setattr(ci.http.client, "HTTPSConnection", Connection)
    return seen


def test_signed_out_get_returns_the_body(ci: ModuleType, https: dict[str, Any]) -> None:
    https["response"] = FakeResponse(200, b'{"full_name": "owner/repo"}', {})

    assert ci.PublicApi().get(f"repos/{REPO}") == {"full_name": REPO}
    method, path, headers = https["request"]
    assert (https["host"], method, path) == ("api.github.com", "GET", f"/repos/{REPO}")
    assert headers["User-Agent"] == "wait-for-ci"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert "Authorization" not in headers
    assert https["closed"]


def test_signed_out_errors_carry_the_status(ci: ModuleType, https: dict[str, Any]) -> None:
    https["response"] = FakeResponse(404, b"{}", {})

    with pytest.raises(ci.ApiError, match="404 Not Found") as caught:
        ci.PublicApi().get(f"repos/{REPO}")
    assert caught.value.status == 404


def test_the_signed_out_limit_says_when_it_resets(ci: ModuleType, https: dict[str, Any]) -> None:
    headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1795462200"}
    https["response"] = FakeResponse(403, b"{}", headers)

    with pytest.raises(ci.RateLimited, match=r"used up until 19:30 UTC\. Install gh"):
        ci.PublicApi().get(f"repos/{REPO}")


def test_a_retry_after_is_rate_limited(ci: ModuleType, https: dict[str, Any]) -> None:
    https["response"] = FakeResponse(429, b"{}", {"Retry-After": "60"})

    with pytest.raises(ci.RateLimited, match=r"used up\. Install gh"):
        ci.PublicApi().get(f"repos/{REPO}")


def test_a_plain_403_is_not_rate_limited(ci: ModuleType, https: dict[str, Any]) -> None:
    https["response"] = FakeResponse(403, b"{}", {"X-RateLimit-Remaining": "12"})

    with pytest.raises(ci.ApiError) as caught:
        ci.PublicApi().get(f"repos/{REPO}")
    assert not isinstance(caught.value, ci.RateLimited)


def test_no_answer_is_transient(ci: ModuleType, https: dict[str, Any]) -> None:
    https["error"] = TimeoutError("timed out")

    with pytest.raises(ci.ApiError, match="timed out") as caught:
        ci.PublicApi().get(f"repos/{REPO}")
    assert caught.value.transient
    assert https["closed"]


# --- the command line --------------------------------------------------------------------------


def test_the_defaults(ci: ModuleType) -> None:
    args = ci.parse_args([])

    assert (args.sha, args.repo, args.timeout) == ("HEAD", None, 540)
    assert ci.parse_args(["--timeout", "1200"]).timeout == 1200


@pytest.mark.parametrize("value", ["0", "-5", "1.5", "soon"])
def test_the_time_limit_is_a_whole_number_of_seconds(ci: ModuleType, value: str) -> None:
    with pytest.raises(SystemExit):
        ci.parse_args(["--timeout", value])


def test_main_waits_and_reports(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test")]})])
    clock = Clock(api)

    code = ci.main(["--repo", REPO, "--sha", SHA], api=api, clock=clock, sleep=clock.sleep)

    assert code == ci.EXIT_PASSED
    out, err = capsys.readouterr()
    assert err.startswith(
        f"Waiting for GitHub Actions on {SHA[:7]} in {REPO}, through the fake API, "
        "checking every 10 s for up to 540 s."
    )
    assert out.strip().endswith("RESULT: PASSED - 1 jobs passed.")


def test_main_picks_the_api_itself(ci: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    api = FakeApi(ci, [([a_run(1)], {1: [a_job(11, "test")]})])
    clock = Clock(api)
    monkeypatch.setattr(ci, "choose_api", lambda repo: api)

    assert ci.main(["--repo", REPO, "--sha", SHA], clock=clock, sleep=clock.sleep) == 0


def test_main_reports_what_it_cannot_check(
    ci: ModuleType, capsys: pytest.CaptureFixture[str]
) -> None:
    code = ci.main(["--repo", "not a repo", "--sha", SHA])

    assert code == ci.EXIT_ERROR
    assert capsys.readouterr().out.startswith("RESULT: COULD NOT CHECK - --repo must look like")


def test_main_reports_an_interrupt(ci: ModuleType, capsys: pytest.CaptureFixture[str]) -> None:
    class Interrupted:
        name = "the fake API"
        interval = 10

        def get(self, path: str) -> Any:
            raise KeyboardInterrupt

    code = ci.main(["--repo", REPO, "--sha", SHA], api=Interrupted())

    assert code == ci.EXIT_INTERRUPTED
    assert capsys.readouterr().out == "RESULT: STOPPED - interrupted.\n"
