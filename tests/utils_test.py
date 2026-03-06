import time
from types import SimpleNamespace

import pytest
from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials

from uiauth import models, secure, utils
from uiauth.enums import APIEndpoints
from tests.conftest import (
    build_credentials,
    make_mock_request,
    TEST_USERNAME,
    TEST_PASSWORD,
)


def make_mock_websocket(
    cookies: dict = None, path: str = "/ws", host: str = "127.0.0.1"
) -> SimpleNamespace:
    """Same rationale as make_mock_request — WebSocket also inherits from Mapping."""
    return SimpleNamespace(
        cookies=cookies or {},
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=host),
    )


@pytest.fixture(autouse=True)
def setup_env():
    models.env = models.env_loader(username=TEST_USERNAME, password=TEST_PASSWORD)


# ---------------------------------------------------------------------------
# failed_auth_counter
# ---------------------------------------------------------------------------


def test_failed_auth_counter_creates_entry():
    request = make_mock_request(host="1.2.3.4")
    utils.failed_auth_counter(request)
    assert models.ws_session.invalid["1.2.3.4"] == 1


def test_failed_auth_counter_increments():
    request = make_mock_request(host="1.2.3.5")
    utils.failed_auth_counter(request)
    utils.failed_auth_counter(request)
    assert models.ws_session.invalid["1.2.3.5"] == 2


def test_failed_auth_counter_redirects_at_three():
    request = make_mock_request(host="1.2.3.6")
    utils.failed_auth_counter(request)
    utils.failed_auth_counter(request)
    with pytest.raises(models.RedirectException) as exc_info:
        utils.failed_auth_counter(request)
    assert exc_info.value.destination == APIEndpoints.fastapi_error


# ---------------------------------------------------------------------------
# raise_error
# ---------------------------------------------------------------------------


def test_raise_error_raises_401():
    request = make_mock_request(host="2.2.2.2")
    with pytest.raises(HTTPException) as exc_info:
        utils.raise_error(request)
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_raise_error_increments_counter():
    request = make_mock_request(host="2.2.2.3")
    with pytest.raises(HTTPException):
        utils.raise_error(request)
    assert models.ws_session.invalid["2.2.2.3"] == 1


# ---------------------------------------------------------------------------
# extract_credentials
# ---------------------------------------------------------------------------


def test_extract_credentials_returns_three_parts():
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    parts = utils.extract_credentials(auth)
    assert len(parts) == 3


def test_extract_credentials_username():
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    username, signature, timestamp = utils.extract_credentials(auth)
    assert username == TEST_USERNAME


def test_extract_credentials_signature_is_sha512():
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    _, signature, _ = utils.extract_credentials(auth)
    assert len(signature) == 128  # SHA-512 hex digest length


# ---------------------------------------------------------------------------
# verify_login
# ---------------------------------------------------------------------------


def test_verify_login_valid_returns_token():
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    request = make_mock_request(host="10.0.0.1")
    token = utils.verify_login(authorization=auth, request=request)
    assert isinstance(token, str)
    assert len(token) > 0


def test_verify_login_resets_invalid_counter():
    host = "10.0.0.2"
    models.ws_session.invalid[host] = 2
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    utils.verify_login(authorization=auth, request=make_mock_request(host=host))
    assert models.ws_session.invalid[host] == 0


def test_verify_login_invalid_username():
    creds = build_credentials("wronguser", TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    with pytest.raises(HTTPException) as exc_info:
        utils.verify_login(
            authorization=auth, request=make_mock_request(host="10.0.0.3")
        )
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_login_invalid_password():
    creds = build_credentials(TEST_USERNAME, "wrongpass")
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    with pytest.raises(HTTPException) as exc_info:
        utils.verify_login(
            authorization=auth, request=make_mock_request(host="10.0.0.4")
        )
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_login_no_authorization():
    with pytest.raises(HTTPException) as exc_info:
        utils.verify_login(
            authorization=None, request=make_mock_request(host="10.0.0.5")
        )
    assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_verify_login_three_failures_redirect():
    """Third consecutive failure triggers redirect to error page instead of 401."""
    request = make_mock_request(host="10.0.0.6")
    creds = build_credentials("wrong", "wrong")
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    for _ in range(2):
        with pytest.raises(HTTPException):
            utils.verify_login(authorization=auth, request=request)
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_login(authorization=auth, request=request)
    assert exc_info.value.destination == APIEndpoints.fastapi_error


# ---------------------------------------------------------------------------
# verify_session
# ---------------------------------------------------------------------------


def test_verify_session_valid():
    host = "192.168.1.1"
    token = "valid-session-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() + 300,
    }
    utils.verify_session(
        api_request=make_mock_request(cookies={"session_token": token}, host=host)
    )


def test_verify_session_expired_redirects_to_login():
    host = "192.168.1.2"
    token = "expired-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() - 1,
    }
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(
            api_request=make_mock_request(cookies={"session_token": token}, host=host)
        )
    assert exc_info.value.destination == APIEndpoints.fastapi_login


def test_verify_session_expired_removes_entry():
    host = "192.168.1.3"
    token = "expired-token-2"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() - 1,
    }
    with pytest.raises(models.RedirectException):
        utils.verify_session(
            api_request=make_mock_request(cookies={"session_token": token}, host=host)
        )
    assert host not in models.ws_session.client_auth


def test_verify_session_no_cookie_redirects_to_login():
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(
            api_request=make_mock_request(cookies={}, host="192.168.1.4")
        )
    assert exc_info.value.destination == APIEndpoints.fastapi_login


def test_verify_session_token_mismatch_redirects_to_session():
    host = "192.168.1.5"
    models.ws_session.client_auth[host] = {
        "token": "correct-token",
        "expires_at": time.time() + 300,
    }
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(
            api_request=make_mock_request(
                cookies={"session_token": "wrong-token"}, host=host
            )
        )
    assert exc_info.value.destination == APIEndpoints.fastapi_session


def test_verify_session_no_request_raises_400():
    with pytest.raises(HTTPException) as exc_info:
        utils.verify_session()
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


def test_verify_session_websocket_valid():
    host = "192.168.1.6"
    token = "ws-valid-token"
    models.ws_session.client_auth[host] = {
        "token": token,
        "expires_at": time.time() + 300,
    }
    ws = make_mock_websocket(cookies={"session_token": token}, host=host)
    utils.verify_session(api_websocket=ws)  # should not raise


def test_verify_session_websocket_no_token():
    ws = make_mock_websocket(cookies={}, host="192.168.1.7")
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(api_websocket=ws)
    assert exc_info.value.destination == APIEndpoints.fastapi_login


# ---------------------------------------------------------------------------
# redirect_exception_handler
# ---------------------------------------------------------------------------


def test_redirect_exception_handler_verify_path_returns_json():
    request = make_mock_request(path=APIEndpoints.fastapi_verify_login)
    exc = models.RedirectException(
        destination=APIEndpoints.fastapi_login, source=APIEndpoints.fastapi_verify_login
    )
    response = utils.redirect_exception_handler(request, exc)
    assert isinstance(response, JSONResponse)


def test_redirect_exception_handler_other_path_returns_redirect():
    request = make_mock_request(path="/some-page")
    exc = models.RedirectException(
        destination=APIEndpoints.fastapi_login, source="/some-page"
    )
    response = utils.redirect_exception_handler(request, exc)
    assert isinstance(response, RedirectResponse)


def test_redirect_exception_handler_sets_x_requested_by_cookie():
    request = make_mock_request(path="/protected")
    exc = models.RedirectException(
        destination=APIEndpoints.fastapi_login, source="/protected"
    )
    response = utils.redirect_exception_handler(request, exc)
    assert "X-Requested-By" in response.headers.get("set-cookie", "")


def test_redirect_exception_handler_sets_detail_cookie_when_present():
    request = make_mock_request(path="/protected")
    exc = models.RedirectException(
        destination=APIEndpoints.fastapi_login, source="/protected", detail="timeout"
    )
    response = utils.redirect_exception_handler(request, exc)
    assert "detail" in response.headers.get("set-cookie", "")


def test_redirect_exception_handler_no_detail_cookie_when_empty():
    request = make_mock_request(path="/protected")
    exc = models.RedirectException(
        destination=APIEndpoints.fastapi_login, source="/protected", detail=""
    )
    response = utils.redirect_exception_handler(request, exc)
    assert "detail" not in response.headers.get("set-cookie", "")


# ---------------------------------------------------------------------------
# deauthorize
# ---------------------------------------------------------------------------


def test_deauthorize_sets_cache_control():
    response = HTMLResponse(content="<h1>test</h1>")
    result = utils.deauthorize(response)
    assert result.headers["Cache-Control"] == "no-cache, no-store, must-revalidate"


def test_deauthorize_clears_authorization_header():
    response = HTMLResponse(content="<h1>test</h1>")
    result = utils.deauthorize(response)
    assert result.headers["Authorization"] == ""


# ---------------------------------------------------------------------------
# clear_session
# ---------------------------------------------------------------------------


def test_clear_session_removes_entry():
    host = "10.10.10.1"
    models.ws_session.client_auth[host] = {"token": "abc", "expires_at": 9999999}
    utils.clear_session(host)
    assert host not in models.ws_session.client_auth


def test_clear_session_missing_host_does_not_raise():
    utils.clear_session("nonexistent-host-xyz")  # should not raise
