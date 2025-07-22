import pytest
from ip_info._format_ownership import _format_ownership

@pytest.mark.parametrize(
    "row,expected",
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
def test_format_ownership(row, expected):
    assert _format_ownership(row) == expected
