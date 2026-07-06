import pytest

from ip_info._ask_yn import ask_yn


def test_ask_yn_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert ask_yn("proceed?") is True


def test_ask_yn_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert ask_yn("proceed?") is False


def test_ask_yn_invalid_true_raises() -> None:
    with pytest.raises(ValueError, match="true must be 'y' or 'n'"):
        ask_yn("proceed?", true="x")


def test_ask_yn_retries_until_valid(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers = iter(["maybe", "y"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert ask_yn("proceed?") is True
    assert "Please enter 'y' or 'n'." in capsys.readouterr().out
