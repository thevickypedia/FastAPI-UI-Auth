import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, status
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from fastapi.requests import Request
from starlette.testclient import TestClient

from uiauth import models, secure, store

TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass"


def build_credentials(username: str, password: str, timestamp: str = None) -> str:
    """Build a valid bearer token string for the given credentials."""
    ts = timestamp or str(int(time.time()))
    hex_user = secure.hex_encode(username)
    hex_pass = secure.hex_encode(password)
    message = f"{hex_user}{hex_pass}{ts}"
    signature = secure.calculate_hash(message)
    raw = f"{username},{signature},{ts}"
    return secure.base64_encode(secure.hex_encode(raw))


def make_mock_request(
    cookies: dict = None,
    path: str = "/test",
    host: str = "127.0.0.1",
    headers: dict = None,
) -> SimpleNamespace:
    """Minimal mock Request (SimpleNamespace, since Request inherits Mapping and MagicMock would be falsy)."""
    return SimpleNamespace(
        cookies=cookies or {},
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=host),
        headers=headers or {},
    )


def failure_count(key: str) -> int:
    """Failed-login count currently stored for a client key."""
    with store._connect() as conn:
        row = conn.execute(
            "SELECT count FROM failures WHERE key = ?", (key,)
        ).fetchone()
    return row[0] if row else 0


@pytest.fixture(autouse=True)
def reset_state(tmp_path, monkeypatch):
    """Isolate every test with a fresh SQLite file and reset module-level state."""
    monkeypatch.setattr(store, "DB_PATH", tmp_path / "fastapi_ui_auth.db")
    store.init()
    models.trusted_proxies = set()
    models.fallback.path = "/"
    models.fallback.button = "LOGIN"
    yield
    models.trusted_proxies = set()


@pytest.fixture
def test_app():
    def protected(_: Request) -> HTMLResponse:
        return HTMLResponse("<h1>Protected</h1>", status_code=status.HTTP_200_OK)

    from uiauth.service import FastAPIUIAuth

    _app = FastAPI()
    FastAPIUIAuth(
        app=_app,
        routes=APIRoute(path="/protected", endpoint=protected),
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        session_timeout=300,
    )
    return _app


@pytest.fixture
def client(test_app):
    return TestClient(test_app, raise_server_exceptions=False, follow_redirects=False)
