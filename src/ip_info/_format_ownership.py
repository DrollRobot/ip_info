import re
from typing import Dict, List


def _normalize_text(text: str) -> str:
    """
    Normalise free-text so string comparisons are reliable.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a str")

    # strip punctuation/symbols/whitespace
    cleaned = re.sub(r"[^0-9A-Za-z]+", "", text)

    # convert to lower case
    cleaned = cleaned.lower()

    return cleaned


def _format_ownership(row:Dict) -> str:
    """Return a canonical ‘ownership’ string from company / ISP / AS-name fields."""

    raw_values: List[str] = [
        row.get("company", ""),
        row.get("isp", ""),
        row.get("as_name", ""),
    ]
    values = [v for v in raw_values if v]

    if not values:
        return ""

    uniques: List[str] = []
    seen_normalised = set()

    for v in values:
        norm = _normalize_text(v)
        if norm not in seen_normalised:
            seen_normalised.add(norm)
            uniques.append(v)

    return ", ".join(uniques)