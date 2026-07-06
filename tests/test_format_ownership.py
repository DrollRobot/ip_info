import pytest

from ip_info._format_ownership import _format_ownership, _normalize_text


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        # de-dupe & preserve order
        ({"company": "Proton AG", "isp": "Proton AG", "as_name": ""}, "Proton AG"),
        # mixed punctuation / case collapse
        ({"company": "Example-Inc!", "isp": "example inc", "as_name": ""}, "Example-Inc!"),
        # all empty → empty string
        ({"company": "", "isp": "", "as_name": ""}, ""),
        # three uniques keep commas
        ({"company": "Acme", "isp": "FooNet", "as_name": "AS123 Foo"}, "Acme, FooNet, AS123 Foo"),
    ],
)
def test_format_ownership(row: dict[str, str], expected: str) -> None:
    assert _format_ownership(row) == expected


def test_normalize_text_rejects_non_str() -> None:
    with pytest.raises(TypeError, match="text must be a str"):
        _normalize_text(123)  # type: ignore[arg-type]
