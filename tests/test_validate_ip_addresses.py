import ipaddress

import pytest

from ip_info._validate_ip_addresses import _validate_ip_addresses


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # valid public v4/v6 kept (2606:4700:4700::1111 is a global address;
        # 2001:db8::/32 would NOT qualify -- it's the reserved documentation range)
        (
            ["1.2.3.4", "2606:4700:4700::1111"],
            [ipaddress.ip_address("1.2.3.4"), ipaddress.ip_address("2606:4700:4700::1111")],
        ),
        # private / link-local are dropped
        (["10.0.0.1", "fe80::1"], []),
        # duplicates folded into one
        (["8.8.8.8", "8.8.8.8"], [ipaddress.ip_address("8.8.8.8")]),
        # junk silently ignored
        (["not-an-ip"], []),
    ],
)
def test_validate_ips(
    raw: list[str],
    expected: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    assert _validate_ip_addresses(user_input=raw, verbose=False) == expected
