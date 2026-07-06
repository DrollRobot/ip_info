"""Tests for ip_info.keys: keyring helpers and the interactive key manager menu."""

import pytest
from keyring.errors import PasswordDeleteError

from ip_info import keys
from ip_info.config import API_METADATA


class FakeKeyring:
    """In-memory stand-in for the keyring module; never touches the OS credential store."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self.store[(service, username)]
        except KeyError as exc:
            raise PasswordDeleteError("no key stored") from exc


@pytest.fixture
def fake_keyring(monkeypatch: pytest.MonkeyPatch) -> FakeKeyring:
    fake = FakeKeyring()
    monkeypatch.setattr(keys, "keyring", fake)
    return fake


def _feed_input(monkeypatch: pytest.MonkeyPatch, responses: list[str]) -> None:
    iterator = iter(responses)

    def fake_input(prompt: str = "") -> str:
        return next(iterator)

    monkeypatch.setattr("builtins.input", fake_input)


def _feed_getpass(monkeypatch: pytest.MonkeyPatch, responses: list[str]) -> None:
    iterator = iter(responses)

    def fake_getpass(prompt: str = "") -> str:
        return next(iterator)

    monkeypatch.setattr("ip_info.keys.getpass.getpass", fake_getpass)


def test_get_api_key_returns_stored_key(fake_keyring: FakeKeyring) -> None:
    fake_keyring.store[("ip_info-someapi", "default")] = "secret"
    assert keys._get_api_key("someapi") == "secret"


def test_get_api_key_returns_none_when_missing(fake_keyring: FakeKeyring) -> None:
    assert keys._get_api_key("someapi") is None


def test_set_api_key_stores_under_expected_service(fake_keyring: FakeKeyring) -> None:
    keys._set_api_key("someapi", "abc123")
    assert fake_keyring.store == {("ip_info-someapi", "default"): "abc123"}


def test_delete_api_key_success(fake_keyring: FakeKeyring) -> None:
    fake_keyring.store[("ip_info-someapi", "default")] = "abc123"
    assert keys._delete_api_key("someapi") is True
    assert fake_keyring.store == {}


def test_delete_api_key_missing_returns_false(fake_keyring: FakeKeyring) -> None:
    assert keys._delete_api_key("someapi") is False


def test_menu_quit_immediately(
    fake_keyring: FakeKeyring,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _feed_input(monkeypatch, ["q"])

    keys.ip_info_keys()

    out = capsys.readouterr().out
    assert "=== API KEY MANAGER ===" in out
    first_display_name = API_METADATA[next(iter(API_METADATA))]["api_display_name"]
    assert f"1. {first_display_name}" in out
    assert "Done." in out


def test_menu_full_flow_covers_every_branch(
    fake_keyring: FakeKeyring,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Outer menu: non-int, out-of-range int, then select the first API.
    # Inner menu: show empty key, set key, show key, set empty key, delete (ok),
    # delete (already gone), delete declined, invalid action, back. Then quit.
    _feed_input(
        monkeypatch,
        [
            "abc",  # outer: ValueError -> invalid choice
            "99",  # outer: IndexError -> invalid choice
            "1",  # outer: select first API
            "1",  # inner: show key (none stored)
            "2",  # inner: set key -> "newkey"
            "1",  # inner: show key (now stored)
            "2",  # inner: set key -> whitespace only, nothing saved
            "3",  # inner: delete
            "y",  # confirm delete -> success
            "3",  # inner: delete again
            "y",  # confirm delete -> fails, no key stored
            "3",  # inner: delete
            "n",  # confirm declined -> no action
            "x",  # inner: invalid action
            "b",  # inner: back to outer menu
            "q",  # outer: quit
        ],
    )
    _feed_getpass(monkeypatch, ["newkey", "   "])

    keys.ip_info_keys()

    out = capsys.readouterr().out
    first_api_name = next(iter(API_METADATA))
    display_name = API_METADATA[first_api_name]["api_display_name"]
    assert out.count("Invalid choice.") == 3
    assert f"--- {display_name} ---" in out
    assert "Current key: No key stored." in out
    assert "Key saved." in out
    assert "Current key: newkey" in out
    assert "Empty key - nothing saved." in out
    assert out.count("Key deleted.") == 1
    assert "No key stored." in out
    assert "Done." in out
    assert fake_keyring.store == {}
