from ip_info._ask_yn import ask_yn

def test_ask_yn_true(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "y")
    assert ask_yn("proceed?") is True

def test_ask_yn_false(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert ask_yn("proceed?") is False
