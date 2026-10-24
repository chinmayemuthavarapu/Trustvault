"""Database access. Plain parameterised SQL over sqlite3.

Every query in this codebase uses `?` placeholders; no SQL is ever built by
string formatting from user input. The authorisation queries are short enough
to read in one sitting, which is the point.
"""
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from flask import current_app, g

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """Fixed-width UTC timestamps so string comparison == time comparison."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_iso() -> str:
    return iso(utcnow())


def iso_in(seconds: float) -> str:
    return iso(utcnow() + timedelta(seconds=seconds))


def new_id() -> str:
    return uuid.uuid4().hex


def connect(path: str) -> sqlite3.Connection:
    # isolation_level=None: we manage transactions explicitly with BEGIN IMMEDIATE.
    conn = sqlite3.connect(path, isolation_level=None, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def init_db(path: str) -> None:
    conn = connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        with open(SCHEMA_PATH, encoding="utf-8") as f:
            conn.executescript(f.read())
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["TV"].DATABASE)
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """A write transaction. BEGIN IMMEDIATE takes the write lock up front, which
    also serialises audit-chain appends (see audit.py)."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")
