"""
Shared pytest fixtures for ip_info tests.
"""

import sqlite3
from collections.abc import Iterator

import pytest

from ip_info.db._initialize_db import ensure_columns_exist, initialize_db


@pytest.fixture
def db_conn() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES)
    initialize_db(conn)
    ensure_columns_exist(conn)
    yield conn
    conn.close()
