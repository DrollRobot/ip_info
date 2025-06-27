import csv
import os
import sys

def load_api_keys(file_path: str | None = None) -> dict[str, str]:
    """
    Load API keys from a CSV file.

    Args:
        file_path: Optional path to api_keys.csv.
                   If None, defaults to the api_keys.csv in this package.

    Returns:
        A dict mapping api_name → api_key.

    Exits with an error message if the file does not exist, isn't readable,
    or doesn’t have a .csv extension.
    """
    # determine which file to load
    if file_path is None:
        base_dir = os.path.dirname(__file__)
        file_path = os.path.join(base_dir, "api_keys.csv")

    # ensure the file exists
    if not os.path.isfile(file_path):
        sys.exit(f"ERROR: API keys file not found: {file_path}")

    # validate extension
    if not file_path.lower().endswith(".csv"):
        sys.exit(f"ERROR: API keys file must have a .csv extension: {file_path}")

    api_keys: dict[str, str] = {}
    try:
        with open(file_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("api_name")
                key  = row.get("api_key")
                if name and key:
                    api_keys[name] = key
    except Exception as e:
        sys.exit(f"ERROR: Failed to load API keys from {file_path}: {e}")

    return api_keys