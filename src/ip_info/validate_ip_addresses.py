import ipaddress

def validate_ip_addresses(user_input: list[str], verbose: bool = False) -> list[str]:
    """
    Validate and filter a list of IPs, keeping only valid public addresses.

    Args:
        user_input: list of strings to validate as IPs
        verbose: if True, print each invalid or non-public IP as it's dropped

    Returns:
        A new list containing only those inputs that parsed as IPv4/IPv6 and are global (public) addresses.
    """
    valid_ips = []
    for string in user_input:
        ip_address = string.strip()
        try:
            addr = ipaddress.ip_address(ip_address)
            if addr.is_global:
                valid_ips.append(ip_address)
            else:
                if verbose:
                    print(f"Removed non-public IP: {ip_address}")
        except ValueError:
            if verbose:
                print(f"Removed invalid IP: {ip_address}")
    return valid_ips
