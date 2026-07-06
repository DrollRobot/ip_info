"""Look up human-readable country names from ISO country codes."""

import csv
import functools
from pathlib import Path


@functools.cache
def _load_country_codes() -> dict[str, str]:
    """Load the ISO country-code -> name map from the bundled CSV (cached).

    The CSV is generated from the IANA tz database's public-domain iso3166.tab
    (shipped by the ``tzdata`` package) and bundled inside the package.
    """
    codes: dict[str, str] = {}
    csv_path = Path(__file__).parent / "iso_country_codes.csv"
    try:
        with open(csv_path, encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for row in reader:
                code, name = row[0], row[1]
                codes[code.upper()] = name
    except FileNotFoundError:
        return {}
    return codes


def get_country_name(country_code: str) -> str | None:
    """Convert a two-letter country code to full country name.

    Args:
        country_code: Two-letter ISO country code (e.g. 'US')

    Returns:
        Full country name if found, None if not found
    """
    return _load_country_codes().get(country_code.upper())
