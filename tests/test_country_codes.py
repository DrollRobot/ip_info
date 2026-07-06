import builtins
import io
from collections.abc import Iterator
from typing import NoReturn

import pytest

from ip_info.country_codes import _load_country_codes, get_country_name

_FAKE_CSV = "code,name\nUS,United States\nDE,Germany\n"


@pytest.fixture(autouse=True)
def _fresh_cache() -> Iterator[None]:
    # every test in this file monkeypatches file access, so clear the
    # functools.cache before AND after so cached state never leaks
    _load_country_codes.cache_clear()
    yield
    _load_country_codes.cache_clear()


def _patch_open_with_fake_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_open(*args: object, **kwargs: object) -> io.StringIO:
        return io.StringIO(_FAKE_CSV)

    monkeypatch.setattr(builtins, "open", _fake_open)


def test_get_country_name_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open_with_fake_csv(monkeypatch)
    assert get_country_name("US") == "United States"


def test_get_country_name_lowercase_input(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open_with_fake_csv(monkeypatch)
    assert get_country_name("de") == "Germany"


def test_get_country_name_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_open_with_fake_csv(monkeypatch)
    assert get_country_name("ZZ") is None


def test_missing_csv_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_open(*args: object, **kwargs: object) -> NoReturn:
        raise FileNotFoundError("iso_country_codes.csv missing")

    monkeypatch.setattr(builtins, "open", _raise_open)
    assert _load_country_codes() == {}
    assert get_country_name("US") is None


def test_bundled_csv_loads() -> None:
    # no monkeypatching: exercise the real CSV shipped inside the package
    codes = _load_country_codes()
    assert len(codes) == 249  # every ISO 3166-1 alpha-2 code
    assert all(len(code) == 2 and code.isupper() for code in codes)
    assert get_country_name("US") == "United States"
    assert get_country_name("de") == "Germany"
