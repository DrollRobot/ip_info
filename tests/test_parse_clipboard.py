import pytest

from ip_info._parse_clipboard import parse_clipboard


def test_parse_clipboard(monkeypatch: pytest.MonkeyPatch) -> None:
    # parse_clipboard() is a pure scraper: it extracts every IP-like token,
    # public OR private. Filtering to public addresses is _validate_ip_addresses'
    # job, so the private 10.0.0.1 below is expected in the raw scrape.
    clip = (
        "Some IPs: 192.0.2.1 or 2001:db8::1234, plus private 10.0.0.1. "
        "The old regex didn't match this address properly: 2603:1036:5:413::5."
    )
    monkeypatch.setattr("pyperclip.paste", lambda: clip)
    assert set(parse_clipboard()) == {
        "192.0.2.1",
        "2001:db8::1234",
        "10.0.0.1",
        "2603:1036:5:413::5",
    }
