import hashlib
import pathlib
import sqlite3
import time
from contextlib import contextmanager
from typing import Iterator

DB_PATH = pathlib.Path.cwd() / "fastapi_ui_auth.db"
FAILURE_TTL = 3600  # failed-attempt counters reset after 1 hour


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """Context manager for SQLite connection with WAL mode enabled.

    Yields:
        sqlite3.Connection: The SQLite connection.
    """
    # autocommit; WAL + busy timeout makes this safe across worker processes
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
    finally:
        conn.close()


def _hash(token: str) -> str:
    """Hash a token using SHA-256.

    Args:
        token: The token to hash.

    Returns:
        str:
        The hashed token.
    """
    # tokens are stored hashed, so a leaked DB file doesn't leak live sessions
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def init() -> None:
    """Create tables (idempotent, safe to call from every worker)."""
    with _connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions "
            "(token TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS failures "
            "(key TEXT PRIMARY KEY, count INTEGER NOT NULL, updated_at REAL NOT NULL)"
        )


def purge() -> None:
    """Purge expired sessions and old failure records."""
    now = time.time()
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM failures WHERE updated_at < ?", (now - FAILURE_TTL,))


def add_session(token: str, ttl: int) -> None:
    """Add a session with a time-to-live (TTL).

    Args:
        token: The session token to add.
        ttl: Time-to-live in seconds.
    """
    purge()
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, expires_at) VALUES (?, ?)",
            (_hash(token), time.time() + ttl),
        )


def session_valid(token: str) -> bool:
    """Check if a session token is valid (exists and not expired).

    Args:
        token: The session token to check.

    Returns:
        bool: True if the session token is valid, False otherwise.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT expires_at FROM sessions WHERE token = ?", (_hash(token),)
        ).fetchone()
    return bool(row and row[0] > time.time())


def delete_session(token: str) -> None:
    """Delete a session token.

    Args:
        token: The session token to delete.
    """
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (_hash(token),))


def record_failure(key: str) -> int:
    """Record a failed attempt and return the current count.

    Args:
        key: The key for which to record the failure.

    Returns:
        int:
        The current failure count for the given key.
    """
    now = time.time()
    with _connect() as conn:
        conn.execute(
            "DELETE FROM failures WHERE key = ? AND updated_at < ?",
            (key, now - FAILURE_TTL),
        )
        conn.execute(
            "INSERT INTO failures (key, count, updated_at) VALUES (?, 1, ?) "
            "ON CONFLICT(key) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at",
            (key, now),
        )
        return conn.execute(
            "SELECT count FROM failures WHERE key = ?", (key,)
        ).fetchone()[0]


def reset_failures(key: str) -> None:
    """Reset the failure count for a given key.

    Args:
        key: The key for which to reset the failure count.
    """
    with _connect() as conn:
        conn.execute("DELETE FROM failures WHERE key = ?", (key,))
