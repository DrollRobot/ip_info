from ip_info._ask_yn import _ask_yn

def test_ask_yn_true(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert _ask_yn("proceed?") is True

def test_ask_yn_false(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert _ask_yn("proceed?") is False
