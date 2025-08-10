import re
import sys
from typing import List

import pyperclip

IPV4_RE = r"""
    \b                       # word boundary
    (?:\d{1,3}\.){3}         # three octets and dots (0–999 each)
    \d{1,3}                  # final octet
    \b                       # word boundary
"""

IPV6_RE = r"""
    (?:[0-9a-f]{0,4}:){2,7}         # 2–7 hextets and colons
    (?:
        (?:                         # IPv4‑mapped tail
            (?:25[0-5]|2[0-4]\d|1?\d{1,2}) \.
        ){3}
        (?:25[0-5]|2[0-4]\d|1?\d{1,2})
      | [0-9a-f]{0,4}               # another hextet
      | :                           # or empty hextet (“::” compression)
    )
"""

IP_RE = re.compile(rf"(?:{IPV4_RE}|{IPV6_RE})", flags=re.IGNORECASE | re.VERBOSE )

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
