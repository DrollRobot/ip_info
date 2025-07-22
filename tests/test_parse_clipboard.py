from ip_info._parse_clipboard import parse_clipboard

def test_parse_clipboard(monkeypatch):
    clip = ("These are public IPs; 192.0.2.1 or 2001:db8::1234. Not 10.0.0.1."
            "The old regex didn't match this address properly: 2603:1036:5:413::5."
    )
    monkeypatch.setattr("pyperclip.paste", lambda: clip)
    assert set(parse_clipboard()) == {
        "192.0.2.1", "2001:db8::1234",
        "2603:1036:5:413::5"
    }