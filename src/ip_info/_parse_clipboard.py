import re
import sys
from typing import List

import pyperclip

IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
IPV6_RE = r"(?:[0-9a-f]{0,4}:){2,7}(?:(?P<ipv4>(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?))|[0-9a-f]{0,4}|:)"
IP_RE = re.compile(f"{IPV4_RE}|{IPV6_RE}", flags=re.IGNORECASE)


def parse_clipboard() -> List[str]:
    """
    Scrape the system clipboard for anything that *looks* like an IPv4/IPv6
    address.
    """

    try:
      raw_text = pyperclip.paste()
    except pyperclip.PyperclipException as exception:
        sys.exit(f"clipboard error: {exception}")

    user_input = IP_RE.findall(raw_text)

    return user_input
