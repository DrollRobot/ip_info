import re
import sys
from typing import List

import pyperclip

_IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
_IPV6_RE = r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b"
_IP_RE = re.compile(f"{_IPV4_RE}|{_IPV6_RE}", flags=re.IGNORECASE)


def _parse_clipboard() -> List[str]:
    """
    Scrape the system clipboard for anything that *looks* like an IPv4/IPv6
    address.
    """

    try:
      raw_text = pyperclip.paste()
    except pyperclip.PyperclipException as exception:
        sys.exit(f"clipboard error: {exception}")

    user_input = _IP_RE.findall(raw_text)

    return user_input
