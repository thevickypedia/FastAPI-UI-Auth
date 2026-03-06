import time

import pytest
from fastapi import FastAPI, status
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from uiauth import models
from uiauth.enums import APIEndpoints
from uiauth.service import FastAPIUIAuth
from tests.conftest import TEST_USERNAME, TEST_PASSWORD


@pytest.fixture
def app_client():
    def protected(_: Request) -> HTMLResponse:
        return HTMLResponse("<h1>Protected</h1>", status_code=status.HTTP_200_OK)

    _app = FastAPI()
    FastAPIUIAuth(
        app=_app,
        routes=APIRoute(path="/protected", endpoint=protected),
        username=TEST_USERNAME,
        password=TEST_PASSWORD,
        timeout=300,
    )
    _client = TestClient(_app, raise_server_exceptions=False, follow_redirects=False)
    return _app, _client


def test_login_page_returns_200(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_login)
    assert response.status_code == 200


def test_login_page_returns_html(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_login)
    assert "text/html" in response.headers["content-type"]


def test_login_page_clears_session_cookie(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_login)
    # deauthorize sets Cache-Control and clears Authorization
    assert "no-cache" in response.headers.get("cache-control", "")


def test_session_page_returns_200(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_session)
    assert response.status_code == 200


def test_session_page_returns_html(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_session)
    assert "text/html" in response.headers["content-type"]


def test_error_page_returns_200(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_error)
    assert response.status_code == 200


def test_error_page_returns_html(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_error)
    assert "text/html" in response.headers["content-type"]


def test_logout_without_session_renders_session_page(app_client):
    _, client = app_client
    response = client.get(APIEndpoints.fastapi_logout)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_logout_with_valid_session_returns_200(app_client):
    _, client = app_client
    host = "testclient"
    token = "logout-test-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() + 300,
    }
    response = client.get(APIEndpoints.fastapi_logout, cookies={"session_token": token})
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_logout_with_expired_session_renders_session_page(app_client):
    _, client = app_client
    host = "testclient"
    token = "expired-logout-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() - 1,
    }
    response = client.get(APIEndpoints.fastapi_logout, cookies={"session_token": token})
    assert response.status_code == 200
