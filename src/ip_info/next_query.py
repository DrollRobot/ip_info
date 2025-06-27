import csv
from datetime import datetime
import os

API_NEXT_QUERY_FILE = os.path.join(os.path.dirname(__file__), "next_query.csv")

def get_next_query_dict(file_path=API_NEXT_QUERY_FILE):
    """
    Reads the api_next_query.csv file and returns a dictionary mapping api_name to next_query_epoch (float).

    If the file does not exist, returns an empty dictionary.
    """
    next_query = {}
    if not os.path.exists(file_path):
        return next_query
    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                next_query[row["api_name"]] = datetime.fromisoformat(
                    row["next_query_date"]
                )
            except ValueError:
                continue
    return next_query


def update_next_query_dict(api_name, next_query_dt, file_path=API_NEXT_QUERY_FILE):
    """
    Updates the next_query_date for the given api_name in the api_next_query.csv file.

    If the file does not exist, it creates it.
    """
    next_query_dict = get_next_query_dict(file_path)
    next_query_dict[api_name] = next_query_dt

    # write the updated dictionary back to the file.
    with open(file_path, mode="w", encoding="utf-8", newline="") as f:
        fieldnames = ["api_name", "next_query_date"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key, dt in next_query_dict.items():
            writer.writerow({"api_name": key, "next_query_date": dt.isoformat()})