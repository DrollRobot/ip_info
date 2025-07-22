"""
Shared pytest fixtures for ip_info tests.
"""
import sqlite3
import pytest

from ip_info.db._initialize_db import initialize_db, ensure_columns_exist

@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    initialize_db(conn)
    ensure_columns_exist(conn)
    yield conn
    conn.close()
