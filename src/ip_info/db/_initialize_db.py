import sqlite3
import sys
from datetime import UTC, datetime

from ip_info.constants import IP_TABLE_NAME, TABLES


def adapt_datetime(dt: datetime) -> str:
    """Convert an aware datetime to the ISO string SQLite stores, always in UTC.

    Storing one offset keeps the text column in time order, so ``ORDER BY
    timestamp`` sorts correctly; display converts back to local time.

    Args:
        dt: A timezone-aware datetime, in any time zone.

    Returns:
        The instant as an ISO 8601 string with a ``+00:00`` offset.

    Raises:
        ValueError: If *dt* is naive: its time zone would be a guess.
    """
    if dt.tzinfo is None:
        raise ValueError("Naive datetimes are not accepted. Use a timezone aware datetime.")
    return dt.astimezone(UTC).isoformat()


# register converter: Convert ISO formatted strings to aware datetime objects.
def convert_datetime(s: bytes) -> datetime:
    return datetime.fromisoformat(s.decode("utf-8"))


sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)


def ensure_columns_exist(db_conn: sqlite3.Connection) -> None:
    """Adds any missing columns to all tables defined in TABLES."""
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    cursor = db_conn.cursor()

    for table in TABLES:
        table_name = table["name"]
        columns_dict = table["columns"]

        # fetch existing column names
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing = {row[1] for row in cursor.fetchall()}

        # add any missing columns
        for column, definition in columns_dict.items():
            if column not in existing:
                cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {definition}")

    db_conn.commit()


def initialize_db(db_conn: sqlite3.Connection) -> None:
    """Creates all tables and their indexes if they don't exist."""
    if db_conn is None:
        sys.exit("ERROR: no database connection provided.")

    cursor = db_conn.cursor()

    for table in TABLES:
        table_name = table["name"]
        columns_dict = table["columns"]
        indexes = table.get("indexes", [])

        # create table
        columns_sql = ",\n".join(
            f"{column} {definition}" for column, definition in columns_dict.items()
        )
        cursor.execute(f"CREATE TABLE IF NOT EXISTS {table_name} (\n{columns_sql}\n)")

        # create indexes
        for index_name, index_columns in indexes:
            statement = (
                f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name}"
                if table_name == IP_TABLE_NAME
                else f"CREATE INDEX IF NOT EXISTS {index_name}"
            )
            cursor.execute(f"{statement} ON {table_name} {index_columns}")

    db_conn.commit()
