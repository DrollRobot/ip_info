from collections.abc import Iterable
from datetime import datetime, timedelta
import json
import os
import sqlite3
import sys
import time

from ip_info.config import LOCAL_TIMEZONE, MAX_AGE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'ip_info.db')

IP_TABLE_NAME = 'ip_data'
IP_TABLE_COLUMNS = {
    "id": "INTEGER PRIMARY KEY AUTOINCREMENT",
    "timestamp": "TIMESTAMP",
    "ip_address": "TEXT",
    "api_name": "TEXT",
    "api_display_name": "TEXT",
    "risk": "INTEGER",
    "city": "TEXT",
    "state": "TEXT",
    "cc": "TEXT",
    "company": "TEXT",
    "isp": "TEXT",
    "as_name": "TEXT",
    "hostname": "TEXT",
    "flags": "TEXT",
    "raw_json": "TEXT"
}
IP_INSERT_ORDER = [
    column
    for column in IP_TABLE_COLUMNS.keys()
    if column != "id"
]

QUERY_TABLE_NAME = "api_queries"
QUERY_TABLE_COLUMNS = {
    "id":        "INTEGER PRIMARY KEY AUTOINCREMENT",
    "api_name":  "TEXT",
    "timestamp": "TIMESTAMP",
    "status_code": "INTEGER",
    "error_text": "TEXT",
}
QUERY_INSERT_ORDER = [
    column
    for column in QUERY_TABLE_COLUMNS.keys()
    if column != "id"
]

TABLES = [
    {
        "name": IP_TABLE_NAME,
        "columns": IP_TABLE_COLUMNS,
        "indexes": [
            (f"idx_{IP_TABLE_NAME}", "(api_name, ip_address)")
        ],
    },
    {
        "name": QUERY_TABLE_NAME,
        "columns": QUERY_TABLE_COLUMNS,
        "indexes": [
            (f"idx_{QUERY_TABLE_NAME}", "(api_name, timestamp)")
        ],
    },
]

# register adapter: Convert aware datetime objects to ISO formatted strings.
def adapt_datetime(dt):
    if dt.tzinfo is None:
        raise ValueError("Naive datetimes are not queries. Use a timezone aware datetime.")
    return dt.isoformat()

# register converter: Convert ISO formatted strings to aware datetime objects.
def convert_datetime(s):
    return datetime.fromisoformat(s.decode("utf-8"))

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)

def store_in_db(*,
        ip_address,
        api_name,
        api_display_name,
        risk,
        city,
        state,
        cc,
        company,
        isp,
        as_name,
        hostname,
        flags,
        raw_json,
        timestamp=None,
        db_conn: sqlite3.Connection = None
):
    """Stores API responses in the database using dynamic column definitions."""

    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    if timestamp is None:
        timestamp = datetime.now().astimezone()

    cursor = db_conn.cursor()
    
    # delete any existing entry for this api_name + ip_address
    cursor.execute(
        f"DELETE FROM {IP_TABLE_NAME} WHERE api_name = ? AND ip_address = ?",
        (api_name, ip_address)
    )

    # build and execute the insert
    placeholders = ", ".join("?" for _ in IP_INSERT_ORDER)
    columns = ", ".join(IP_INSERT_ORDER)
    query = f"INSERT INTO {IP_TABLE_NAME} ({columns}) VALUES ({placeholders})"
    cursor.execute(query, (
        timestamp,
        ip_address,
        api_name,
        api_display_name,
        risk,
        city,
        state,
        cc,
        company,
        isp,
        as_name,
        hostname,
        flags,
        json.dumps(raw_json)
    ))

    db_conn.commit()


def check_rate_limits(
    api_name: str,
    rate_limits: list[dict],
    db_conn: sqlite3.Connection
) -> bool:
    """
    Enforce rate_limits for api_name, supporting 'rolling' or 'absolute' windows.

    Accepts rate_limits dict. Should have one entry for each type of rate limit the 
    provider has. (per second, per hour, daily, monthly, etc...)

    rolling - Indicates a rolling limit. For example, with a daily rolling limit,
    queries from the last 24 hours are looked at. 

    absolute - Indicates a limit that starts at the beginning of a whole period. For
    example, an absolute daily limit means the counter starts at 12:00am and ends at
    11:59pm. 

    status_code,error_text - If a query returns this status code(and error_text if 
    present), it means the rate limit has been reached. No further queries for the given 
    time period.

    rate_limits = [
        {
            "query_limit": 4,
            "timeframe":   "minute",
            "type":        "rolling",
            "status_code": 429
        },
        {
            "query_limit": 1000,
            "timeframe":   "day",
            "type":        "absolute",
            "status_code": 429,
            "error_text":  "Too Many Requests"
        },
    ]

    Returns:
      True - No rate limit reached. Proceed with query.
      False - Rate limit reached. Do not query.
    """
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")
    
    # pull all table entries for this api_name
    db_conn.row_factory = sqlite3.Row
    cursor = db_conn.cursor()
    cursor.execute(
        f"""
        SELECT *
        FROM {QUERY_TABLE_NAME}
        WHERE api_name = ?
        ORDER BY timestamp
        """,
        (api_name,)
    )
    rows = cursor.fetchall()

    now = datetime.now(LOCAL_TIMEZONE)

    for rate_limit in rate_limits:

        query_limit = rate_limit["query_limit"]
        timeframe = rate_limit["timeframe"]
        mode = rate_limit.get("type", "rolling")
        status_code = rate_limit.get("status_code")
        error_text = rate_limit.get("error_text")
        limit_text = f"{query_limit}/{timeframe}"

        # build window starting from current time
        if mode == "rolling":
            if timeframe == "second":
                window = timedelta(seconds=1)
            elif timeframe == "minute":
                window = timedelta(minutes=1)
            elif timeframe == "hour":
                window = timedelta(hours=1)
            elif timeframe == "day":
                window = timedelta(days=1)
            elif timeframe == "month":
                window = timedelta(days=30)
            else:
                raise ValueError(f"Unknown timeframe: {timeframe!r}")
            
            cutoff = now - window
            timeframe_rows = [row for row in rows if row["timestamp"] >= cutoff]

        # build window from start to end of current second/minute/day/etc...
        elif mode == "absolute":
            if timeframe == "second":
                start = now.replace(microsecond=0)
                end   = start + timedelta(seconds=1)
            elif timeframe == "minute":
                start = now.replace(second=0, microsecond=0)
                end   = start + timedelta(minutes=1)
            elif timeframe == "hour":
                start = now.replace(minute=0, second=0, microsecond=0)
                end   = start + timedelta(hours=1)
            elif timeframe == "day":
                start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                end   = start + timedelta(days=1)
            elif timeframe == "month":
                start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                if now.month == 12:
                    end = start.replace(year=now.year+1, month=1)
                else:
                    end = start.replace(month=now.month+1)
            else:
                raise ValueError(f"Unknown timeframe: {timeframe!r}")

            timeframe_rows = [row for row in rows if start <= row["timestamp"] < end] #FIXME

        else:
            raise ValueError(f"type must be 'rolling' or 'absolute', got {mode!r}")

        # if query limit exceeded
        if len(timeframe_rows) >= query_limit:
            # if seconds, wait until next second and return true
            if timeframe == "second":
                # compute sleep duration
                if mode == "rolling":
                    last_call = max(timeframe_rows) #FIXME
                    wake_at   = last_call + timedelta(seconds=1)
                else:  # absolute: wake at next boundary
                    wake_at = end
                wait = (wake_at - now).total_seconds()
                if wait > 0:
                    time.sleep(wait)
                query_check =  True
            # if anything other than seconds, return false
            else:
                print(f"{api_name} limit hit: {limit_text}")
                query_check = False
        # if query limit not exceeded, return true
        else:
            query_check = True

        # check if error message found
        status_code_rows = [row for row in timeframe_rows if row["status_code"] == status_code]
        if status_code_rows:
            if error_text:
                error_check = any(error_text in row["error_text"] for row in status_code_rows)
                error_check = not error_check
            else:
                error_check = False
        # return true if no queries match
        else:
            error_check = True

        # if both tests true, return true to allow query
        if query_check and error_check:
            return True
        # if either test failed, return false to prevent query
        else:
            return False
            


def insert_ip_info(*, entries: list[dict], db_conn: sqlite3.Connection):
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
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    # validate correct input
    if not isinstance(entries, Iterable):
        sys.exit(
            "ERROR: insert_ip_info expects an iterable (e.g. list) of dicts.\n"
            "       Pass a single entry as [entry] instead of entry."
        )

    # prepare columns and SQL
    placeholders = ", ".join("?" for _ in IP_INSERT_ORDER)
    # on conflict key:
    key = "(api_name, ip_address)"
    # update all columns except the key columns
    update_cols = [c for c in IP_INSERT_ORDER if c not in ("api_name", "ip_address")]
    update_clause = ", ".join(f"{c}=excluded.{c}" for c in update_cols)

    sql = (
        f"INSERT INTO {IP_TABLE_NAME} ({', '.join(IP_INSERT_ORDER)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT{key} DO UPDATE SET {update_clause}"
    )

    # Helper: convert a dict record → tuple of params
    def _record_to_tuple(rec: dict):
        return tuple(
            rec[c] if c != "raw_json" else json.dumps(rec[c])
            for c in IP_INSERT_ORDER
        )

    cursor = db_conn.cursor()
    params = [_record_to_tuple(rec) for rec in entries]

    cursor.executemany(sql, params)
    db_conn.commit()


def insert_query_info(api_name: str, response, db_conn: sqlite3.Connection = None):
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


# FIXME remove after all db functions updated
def delete_from_db(api_name, ip_address, db_conn: sqlite3.Connection = None):
    """Deletes the stored response for the given API and IP address."""

    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    cursor = db_conn.cursor()
    cursor.execute(
        f"DELETE FROM {IP_TABLE_NAME} WHERE api_name = ? AND ip_address = ?",
        (api_name, ip_address)
    )
    db_conn.commit()


def ensure_columns_exist(db_conn: sqlite3.Connection = None):
    """
    Adds any missing columns to all tables defined in TABLES.
    """
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    cursor = db_conn.cursor()

    for table in TABLES:
        table_name  = table["name"]
        columns_dict = table["columns"]

        # fetch existing column names
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing = {row[1] for row in cursor.fetchall()}

        # add any missing columns
        for column, definition in columns_dict.items():
            if column not in existing:
                cursor.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column} {definition}"
                )

    db_conn.commit()


def fetch_ip_info(api_names, ip_address, db_conn: sqlite3.Connection = None):
    """
    Fetches stored responses for given API names and IP address.
    If api_names is 'all', returns all records for that IP_address.
    Returns a list of dicts.
    """
    # normalize to list
    if isinstance(api_names, str):
        api_names = [api_names]

    # build query
    if api_names == ["all"]:
        # ignore api_name filter
        query = (
            f"SELECT * FROM {IP_TABLE_NAME} "
            "WHERE ip_address = ?"
        )
        params = [ip_address]
    else:
        placeholders = ", ".join("?" for _ in api_names)
        query = (
            f"SELECT * FROM {IP_TABLE_NAME} "
            f"WHERE api_name IN ({placeholders}) "
            "AND ip_address = ?"
        )
        params = api_names + [ip_address]

    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    db_conn.row_factory = sqlite3.Row
    cursor = db_conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()

    return [dict(row) for row in rows]


def initialize_db(db_conn: sqlite3.Connection = None):
    """Creates all tables and their indexes if they don't exist."""
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    cursor = db_conn.cursor()

    for table in TABLES:
        table_name    = table["name"]
        columns_dict   = table["columns"]
        indexes        = table.get("indexes", [])

        # create table
        columns_sql = ",\n".join(f"{column} {definition}"
                              for column, definition in columns_dict.items())
        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {table_name} (\n{columns_sql}\n)"
        )

        # create indexes
        for index_name, index_columns in indexes:
            statement = (
                f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name}"
                if table_name == IP_TABLE_NAME
                else f"CREATE INDEX IF NOT EXISTS {index_name}"
            )
            cursor.execute(
                f"{statement} ON {table_name} {index_columns}"
            )

    db_conn.commit()


def is_ip_info_recent(api_name, ip_address, db_conn: sqlite3.Connection = None, max_age=MAX_AGE):
    """
    Checks if a database entry for the specified API and IP address is recent.
    Returns True if at least one entry is within max_age days.
    """
    # reuse fetch_ip_info, passing along db_conn
    entries = fetch_ip_info(api_name, ip_address, db_conn=db_conn)
    if not entries:
        return False

    tz = entries[0].get("timestamp").tzinfo
    now = datetime.now(tz)
    cutoff = now - timedelta(days=max_age)

    return any(
        entry.get("timestamp") and entry["timestamp"] >= cutoff
        for entry in entries
    )
