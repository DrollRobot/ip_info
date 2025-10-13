import csv
from pathlib import Path
from typing import Dict, Optional

def get_country_name(country_code: str) -> Optional[str]:
    """Convert a two-letter country code to full country name.
    
    Args:
        country_code: Two-letter ISO country code (e.g. 'US')
        
    Returns:
        Full country name if found, None if not found
    """
    # Create cache for country codes
    if not hasattr(get_country_name, '_country_codes'):
        get_country_name._country_codes: Dict[str, str] = {}
        
        # Load country codes from CSV
        csv_path = Path(__file__).parent.parent / 'iso_country_codes.csv'
        try:
            with open(csv_path, mode='r', encoding='utf-8') as f:
                reader = csv.reader(f)
                next(reader)  # Skip header row
                for row in reader:
                    code, name = row[0], row[1]
                    get_country_name._country_codes[code.upper()] = name
        except FileNotFoundError:
            return None
            
    # Look up country name
    return get_country_name._country_codes.get(country_code.upper())