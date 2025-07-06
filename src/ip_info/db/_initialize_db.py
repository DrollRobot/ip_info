from datetime import datetime
import sqlite3
import sys

from ip_info.config import IP_TABLE_NAME, TABLES

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

def ensure_columns_exist(db_conn: sqlite3.Connection):
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


def initialize_db(db_conn: sqlite3.Connection):
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