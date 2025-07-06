import ipaddress
from typing import List

def _validate_ip_addresses(
    *,
    user_input: list[str], 
    verbose: bool = True
) -> list[str]:
    """
    Validate and filter a list of IPs, keeping only valid public addresses.

    Args:
        user_input: list of strings to validate as IPs
        verbose: if True, print each invalid or non-public IP as it's dropped

    Returns:
        A new list containing only those inputs that parsed as IPv4/IPv6 and are global (public) addresses.
    """
    valid_ips: List[str] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

    for string in user_input:
        string = string.strip()
        try:
            address_obj = ipaddress.ip_address(string)
            if address_obj.is_global:
                if address_obj not in seen:
                    valid_ips.append(str(address_obj))
                    seen.add(address_obj)
                elif verbose:
                    print(f"Removed duplicate IP: {string}")
            else:
                if verbose:
                    print(f"Removed non-public IP: {string}")
        except ValueError:
            if verbose:
                print(f"Removed invalid IP: {string}")

    return valid_ips