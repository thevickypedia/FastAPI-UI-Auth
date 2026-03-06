import logging
import time

import pytest
from fastapi import FastAPI, status
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.testclient import TestClient

from uiauth import models, secure
from uiauth.enums import APIEndpoints
from uiauth.service import FastAPIUIAuth
from tests.conftest import TEST_USERNAME, TEST_PASSWORD, build_credentials


def protected_endpoint(_: Request) -> HTMLResponse:
    return HTMLResponse("<h1>Protected</h1>", status_code=status.HTTP_200_OK)


@pytest.fixture
def base_app():
    return FastAPI()


@pytest.fixture
def protected_route():
    return APIRoute(path="/protected", endpoint=protected_endpoint)


@pytest.fixture
def auth_app():
    _app = FastAPI()
    FastAPIUIAuth(
        app=_app,
        routes=APIRoute(path="/protected", endpoint=protected_endpoint),
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        timeout=300,
    )
    return _app


@pytest.fixture
def client(auth_app):
    return TestClient(auth_app, raise_server_exceptions=False, follow_redirects=False)


# ---------------------------------------------------------------------------
# __init__ validation
# ---------------------------------------------------------------------------


def test_init_valid(base_app, protected_route):
    auth = FastAPIUIAuth(
        app=base_app,
        routes=protected_route,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
    )
    assert auth.timeout == 300


def test_init_custom_timeout(base_app, protected_route):
    auth = FastAPIUIAuth(
        app=base_app,
        routes=protected_route,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        timeout=60,
    )
    assert auth.timeout == 60


def test_init_timeout_too_low_raises(base_app, protected_route):
    with pytest.raises(AssertionError, match="Timeout"):
        FastAPIUIAuth(
            app=base_app,
            routes=protected_route,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            timeout=10,
        )


def test_init_timeout_boundary_passes(base_app, protected_route):
    auth = FastAPIUIAuth(
        app=base_app,
        routes=protected_route,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        timeout=30,
    )
    assert auth.timeout == 30


def test_init_timeout_not_int_raises(base_app, protected_route):
    with pytest.raises(AssertionError, match="Timeout"):
        FastAPIUIAuth(
            app=base_app,
            routes=protected_route,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            timeout="300",
        )


def test_init_missing_credentials_raises(base_app, protected_route, monkeypatch):
    for var in ("USERNAME", "PASSWORD", "USER", "PASS", "user", "pass"):
        monkeypatch.delenv(var, raising=False)
    # Pydantic v2 raises ValidationError (ValueError) before the assert fires;
    # either way the init must fail when no credentials can be resolved.
    with pytest.raises((AssertionError, ValueError)):
        FastAPIUIAuth(
            app=base_app, routes=protected_route, username=None, password=None
        )


def test_init_not_fastapi_app_raises(protected_route):
    with pytest.raises(AssertionError, match="FastAPI"):
        FastAPIUIAuth(
            app=object(),
            routes=protected_route,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
        )


def test_init_single_apiwebsocketroute(base_app):
    async def ws_endpoint(websocket):
        await websocket.accept()

    auth = FastAPIUIAuth(
        app=base_app,
        routes=APIWebSocketRoute(path="/ws", endpoint=ws_endpoint),
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
    )
    assert len(auth.routes) == 1


def test_init_list_of_routes(base_app):
    def endpoint2(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    routes = [
        APIRoute(path="/a", endpoint=protected_endpoint),
        APIRoute(path="/b", endpoint=endpoint2),
    ]
    auth = FastAPIUIAuth(
        app=base_app,
        routes=routes,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
    )
    assert len(auth.routes) == 2


def test_init_empty_routes_list_raises(base_app):
    with pytest.raises(AssertionError, match="No endpoints"):
        FastAPIUIAuth(
            app=base_app,
            routes=[],
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
        )


def test_init_invalid_route_type_raises(base_app):
    with pytest.raises(ValueError, match="Routes must be"):
        FastAPIUIAuth(
            app=base_app,
            routes="/not-a-route",
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
        )


def test_init_invalid_route_in_list_raises(base_app):
    with pytest.raises(AssertionError):
        FastAPIUIAuth(
            app=base_app,
            routes=["/not-a-route"],
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
        )


def test_init_fallback_path_without_slash_raises(base_app, protected_route):
    with pytest.raises(AssertionError, match="Fallback path"):
        FastAPIUIAuth(
            app=base_app,
            routes=protected_route,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            fallback_path="no-slash",
        )


def test_init_custom_fallback(base_app, protected_route):
    FastAPIUIAuth(
        app=base_app,
        routes=protected_route,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        fallback_button="GO BACK",
        fallback_path="/home",
    )
    assert models.fallback.button == "GO BACK"
    assert models.fallback.path == "/home"


def test_init_custom_logger(base_app, protected_route):
    custom = logging.getLogger("test_custom_logger")
    FastAPIUIAuth(
        app=base_app,
        routes=protected_route,
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        custom_logger=custom,
    )
    from uiauth import logger

    assert logger.CUSTOM_LOGGER is custom


def test_init_invalid_custom_logger_raises(base_app, protected_route):
    with pytest.raises(AssertionError, match="logging.Logger"):
        FastAPIUIAuth(
            app=base_app,
            routes=protected_route,
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            custom_logger="not-a-logger",
        )


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------


def test_all_auth_routes_registered(auth_app):
    paths = {r.path for r in auth_app.routes if hasattr(r, "path")}
    assert APIEndpoints.fastapi_login in paths
    assert APIEndpoints.fastapi_logout in paths
    assert APIEndpoints.fastapi_verify_login in paths
    assert APIEndpoints.fastapi_session in paths
    assert APIEndpoints.fastapi_error in paths
    assert "/protected" in paths


def test_conflicting_route_removed_and_reregistered():
    """A route already on the app should be removed and re-added with auth dependency."""
    _app = FastAPI()
    _app.routes.append(APIRoute(path="/protected", endpoint=protected_endpoint))
    original_count = sum(
        1 for r in _app.routes if hasattr(r, "path") and r.path == "/protected"
    )
    assert original_count == 1

    FastAPIUIAuth(
        app=_app,
        routes=APIRoute(path="/protected", endpoint=protected_endpoint),
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
    )
    final_count = sum(
        1 for r in _app.routes if hasattr(r, "path") and r.path == "/protected"
    )
    assert final_count == 1


# ---------------------------------------------------------------------------
# _verify_auth integration
# ---------------------------------------------------------------------------


def test_verify_auth_valid_returns_redirect_url(client):
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    response = client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    assert response.status_code == 200
    assert response.json()["redirect_url"] == "/protected"


def test_verify_auth_valid_sets_session_cookie(client):
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    response = client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    assert "session_token" in response.cookies


def test_verify_auth_stores_session_server_side(client):
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    assert len(models.ws_session.client_auth) == 1
    stored = list(models.ws_session.client_auth.values())[0]
    assert "token" in stored
    assert "expires_at" in stored
    assert stored["expires_at"] > time.time()


def test_verify_auth_missing_x_requested_by_returns_417(client):
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    response = client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
    )
    assert response.status_code == 417


def test_verify_auth_invalid_credentials_returns_401(client):
    creds = build_credentials(TEST_USERNAME, "wrong-password")
    response = client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    assert response.status_code == 401


def test_verify_auth_missing_authorization_returns_401(client):
    # When no Authorization header is provided, authorization=None reaches
    # verify_login which calls raise_error → 401 Unauthorized
    response = client.post(
        APIEndpoints.fastapi_verify_login,
        cookies={"X-Requested-By": "/protected"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Protected route access
# ---------------------------------------------------------------------------


def test_protected_route_without_session_redirects(client):
    response = client.get("/protected")
    assert response.status_code in (302, 307)
    assert APIEndpoints.fastapi_login in response.headers.get("location", "")


def test_protected_route_with_valid_session_returns_200(auth_app):
    """Full login → access flow."""
    _client = TestClient(
        auth_app, raise_server_exceptions=False, follow_redirects=False
    )
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)

    verify_response = _client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    assert verify_response.status_code == 200
    session_token = verify_response.cookies.get("session_token")
    assert session_token

    protected_response = _client.get(
        "/protected", cookies={"session_token": session_token}
    )
    assert protected_response.status_code == 200


def test_protected_route_with_expired_session_redirects(auth_app):
    _client = TestClient(
        auth_app, raise_server_exceptions=False, follow_redirects=False
    )
    host = "testclient"
    token = "stale-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() - 1,
    }
    response = _client.get("/protected", cookies={"session_token": token})
    assert response.status_code in (302, 307)
    assert APIEndpoints.fastapi_login in response.headers.get("location", "")


def test_multiple_logins_overwrite_session(auth_app):
    """Second login should replace the first session, not accumulate timers."""
    _client = TestClient(
        auth_app, raise_server_exceptions=False, follow_redirects=False
    )
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)

    _client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    first_token = list(models.ws_session.client_auth.values())[0]["token"]

    _client.post(
        APIEndpoints.fastapi_verify_login,
        headers={"Authorization": f"Bearer {creds}"},
        cookies={"X-Requested-By": "/protected"},
    )
    second_token = list(models.ws_session.client_auth.values())[0]["token"]

    # Only one entry should exist (not accumulated)
    assert len(models.ws_session.client_auth) == 1
    # The session should have been refreshed
    assert first_token != second_token
