import sqlite3
from datetime import UTC, datetime
from typing import cast

import pytest

from ip_info.config import IP_TABLE_NAME, QUERY_TABLE_NAME, TABLES
from ip_info.db._initialize_db import (
    adapt_datetime,
    convert_datetime,
    ensure_columns_exist,
    initialize_db,
)


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    cur = conn.execute(f"PRAGMA table_info({table_name})")
    return {row[1] for row in cur.fetchall()}


def _index_uniqueness(conn: sqlite3.Connection, table_name: str) -> dict[str, int]:
    """Map index name -> unique flag (1 unique, 0 not) from PRAGMA index_list."""
    cur = conn.execute(f"PRAGMA index_list({table_name})")
    return {row[1]: row[2] for row in cur.fetchall()}


def test_adapt_datetime_aware_returns_isoformat() -> None:
    dt = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert adapt_datetime(dt) == dt.isoformat()


def test_adapt_datetime_naive_raises_value_error() -> None:
    with pytest.raises(ValueError, match="timezone aware"):
        adapt_datetime(datetime(2026, 1, 2, 3, 4, 5))


def test_convert_datetime_returns_aware_datetime() -> None:
    dt = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    restored = convert_datetime(dt.isoformat().encode("utf-8"))
    assert restored == dt
    assert restored.tzinfo is not None


def test_initialize_db_creates_tables_and_indexes() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        initialize_db(conn)

        cur = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        table_names = {row[0] for row in cur.fetchall()}
        for table in TABLES:
            assert table["name"] in table_names
            assert _table_columns(conn, table["name"]) == set(table["columns"])

        # the ip_data index is UNIQUE, the api_queries one is not
        assert _index_uniqueness(conn, IP_TABLE_NAME)[f"idx_{IP_TABLE_NAME}"] == 1
        assert _index_uniqueness(conn, QUERY_TABLE_NAME)[f"idx_{QUERY_TABLE_NAME}"] == 0
    finally:
        conn.close()


def test_initialize_db_requires_connection() -> None:
    with pytest.raises(SystemExit):
        initialize_db(cast(sqlite3.Connection, None))


def test_ensure_columns_exist_adds_missing_column() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        initialize_db(conn)
        conn.execute(f"ALTER TABLE {IP_TABLE_NAME} DROP COLUMN flags")
        assert "flags" not in _table_columns(conn, IP_TABLE_NAME)

        ensure_columns_exist(conn)

        assert "flags" in _table_columns(conn, IP_TABLE_NAME)
    finally:
        conn.close()


def test_ensure_columns_exist_noop_when_schema_complete() -> None:
    conn = sqlite3.connect(":memory:")
    try:
        initialize_db(conn)
        before = {table["name"]: _table_columns(conn, table["name"]) for table in TABLES}

        ensure_columns_exist(conn)

        after = {table["name"]: _table_columns(conn, table["name"]) for table in TABLES}
        assert after == before
    finally:
        conn.close()


def test_ensure_columns_exist_requires_connection() -> None:
    with pytest.raises(SystemExit):
        ensure_columns_exist(cast(sqlite3.Connection, None))
