from collections.abc import Iterable, Mapping
from datetime import datetime
import json
import sqlite3
import sys

from ip_info.config import IP_INSERT_ORDER, IP_TABLE_NAME, LOCAL_TIMEZONE, QUERY_TABLE_NAME


def _insert_ip_info(*, entries: list[dict], db_conn: sqlite3.Connection):
    """
    Upsert a batch of API-response rows in one go.

    Args:
      entries: list of dicts, each containing keys:
        timestamp, ip_address, api_name, api_display_name,
        risk, city, state, cc, company, isp, as_name,
        hostname, flags, raw_json
      db_conn: an open sqlite3.Connection

    Behavior:
      - Builds a single INSERT ... ON CONFLICT(...) DO UPDATE statement.
      - Executes it via cursor.executemany() over all entries.
      - Commits once at the end.
    """
    def _record_to_tuple(entry: dict) -> tuple:
        """
        Convert a record dict into a tuple that follows IP_INSERT_ORDER.
        The raw_json column is serialised to a JSON string.
        """
        values = []

        for column in IP_INSERT_ORDER:
            value = entry[column]

            # Serialize the raw JSON payload so it can be stored as text.
            if column == "raw_json":
                value = json.dumps(value)

            values.append(value)

        return tuple(values)

    # exit if no db connection passed
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    # validate an array of dictionaries was passed, not a single dictionary
    if isinstance(entries, Mapping):
        sys.exit(
            "_insert_ip_info expects an *iterable* of dicts – "
            "wrap a single record in [...]"
        )
    if not isinstance(entries, Iterable):
        sys.exit(
            "_insert_ip_info expects an iterable (e.g. list) of dicts."
        )
    if any(not isinstance(r, Mapping) for r in entries):
        sys.exit("Every item in entries must be a dict.")

    # on conflict key:
    key = "(api_name, ip_address)"
    
    # update all columns except the key columns
    columns_to_update = []
    for column_name in IP_INSERT_ORDER:
        if column_name not in ("api_name", "ip_address"):
            columns_to_update.append(column_name)

    assignment_statements = []
    for column_name in columns_to_update:
        assignment_statements.append(f"{column_name} = excluded.{column_name}")

    update_clause = ", ".join(assignment_statements)

    # build sql statement
    placeholders = ", ".join("?" for _ in IP_INSERT_ORDER)
    sql = (
        f"INSERT INTO {IP_TABLE_NAME} ({', '.join(IP_INSERT_ORDER)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT{key} DO UPDATE SET {update_clause}"
    )

    cursor = db_conn.cursor()
    params = [_record_to_tuple(entry) for entry in entries]

    cursor.executemany(sql, params)
    db_conn.commit()


def _insert_query_info(api_name: str, response, db_conn: sqlite3.Connection):
    """
    Log each API call into the query-log table.

    Args:
        api_name:  the api_name string
        response:  the `requests.get(...)` Response
        db_conn:   an open sqlite3.Connection
    """
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    # capture when this call happened
    timestamp = datetime.now(LOCAL_TIMEZONE)

    # status and any error body
    status = response.status_code
    error_text = response.reason

    cursor = db_conn.cursor()
    cursor.execute(
        f"INSERT INTO {QUERY_TABLE_NAME}"
        " (api_name, timestamp, status_code, error_text) "
        "VALUES (?, ?, ?, ?)",
        (api_name, timestamp, status, error_text)
    )
    db_conn.commit()