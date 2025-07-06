import re
import sys
from typing import List

import pyperclip

_IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_IPV6_RE = r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b"
_IP_RE = re.compile(f"{_IPV4_RE}|{_IPV6_RE}", flags=re.IGNORECASE)


def _parse_clipboard(
    *, 
    verbose: bool = True, 
    ask_user: bool = True
) -> List[str]:
    """
    Scrape the system clipboard for anything that *looks* like an IPv4/IPv6
    address.

    If ask_user is True (default) we ask for confirmation before
    touching the clipboard.  A negative response exits the program.

    Parameters
    ----------
    verbose : bool
        Print how many candidate IPs were found.
    ask_user : bool
        Whether to prompt the caller before reading the clipboard.

    Returns
    -------
    list[str]
        A (possibly empty) list of IP-like strings.
    """
    if ask_user:
        try:
            reply = input(
                "No IP addresses were supplied. "
                "Parse the clipboard for IP addresses? [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            reply = "n"

        if reply not in {"y", "yes"}:
            sys.exit("Exiting - clipboard parsing declined.")

    try:
      raw_text = pyperclip.paste()
    except pyperclip.PyperclipException as exception:
        sys.exit(f"clipboard error: {exception}")

    ip_addresses = _IP_RE.findall(raw_text)

    if not ip_addresses:
        sys.exit("No IP addresses supplied and none detected in clipboard.")

    if verbose:
        print(f"Found {len(ip_addresses)} potential IPs in clipboard")

    return ip_addresses
