import subprocess
import sys
import time

from tests.conftest import failure_count
from uiauth import store


def _raw_sessions():
    with store._connect() as conn:
        return conn.execute("SELECT token, expires_at FROM sessions").fetchall()


def test_init_is_idempotent():
    store.init()
    store.init()


def test_add_session_makes_token_valid():
    store.add_session("tok", 60)
    assert store.session_valid("tok")


def test_unknown_token_is_invalid():
    assert not store.session_valid("never-issued")


def test_expired_token_is_invalid():
    store.add_session("old", -1)
    assert not store.session_valid("old")


def test_tokens_are_stored_hashed():
    store.add_session("plain-token", 60)
    [(stored, _)] = _raw_sessions()
    assert stored != "plain-token"
    assert stored == store._hash("plain-token")


def test_re_adding_token_refreshes_expiry():
    store.add_session("tok", 10)
    store.add_session("tok", 500)
    [(_, expires_at)] = _raw_sessions()
    assert expires_at > time.time() + 400


def test_delete_session_revokes_token():
    store.add_session("tok", 60)
    store.delete_session("tok")
    assert not store.session_valid("tok")


def test_delete_unknown_session_is_noop():
    store.delete_session("never-issued")


def test_purge_removes_expired_sessions_and_stale_failures():
    store.add_session("live", 60)
    with store._connect() as conn:
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?)",
            (store._hash("dead"), time.time() - 5),
        )
        conn.execute(
            "INSERT INTO failures VALUES (?, ?, ?)",
            ("1.1.1.1", 2, time.time() - store.FAILURE_TTL - 5),
        )
        conn.execute(
            "INSERT INTO failures VALUES (?, ?, ?)", ("2.2.2.2", 1, time.time())
        )
    store.purge()
    assert len(_raw_sessions()) == 1
    assert store.session_valid("live")
    assert failure_count("1.1.1.1") == 0
    assert failure_count("2.2.2.2") == 1


def test_record_failure_counts_up():
    assert [store.record_failure("1.1.1.1") for _ in range(3)] == [1, 2, 3]


def test_record_failure_restarts_after_ttl():
    with store._connect() as conn:
        conn.execute(
            "INSERT INTO failures VALUES (?, ?, ?)",
            ("1.1.1.1", 5, time.time() - store.FAILURE_TTL - 5),
        )
    assert store.record_failure("1.1.1.1") == 1


def test_reset_failures():
    store.record_failure("1.1.1.1")
    store.reset_failures("1.1.1.1")
    assert failure_count("1.1.1.1") == 0


def test_session_visible_to_another_process():
    """The original bug: a session created in one process must validate in another."""
    store.add_session("shared-token", 60)
    code = (
        "import pathlib, sys\n"
        "from uiauth import store\n"
        f"store.DB_PATH = pathlib.Path({str(store.DB_PATH)!r})\n"
        "sys.exit(0 if store.session_valid('shared-token') else 1)\n"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
