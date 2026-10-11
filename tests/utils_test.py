import time
from types import SimpleNamespace

import pytest
from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials

from uiauth.enums import APIEndpoints
from uiauth import models, secure, store, utils
from tests.conftest import (
    build_credentials,
    failure_count,
    make_mock_request,
    TEST_USERNAME,
    TEST_PASSWORD,
)


def make_mock_websocket(
    cookies: dict = None, path: str = "/ws", host: str = "127.0.0.1", headers: dict = None
) -> SimpleNamespace:
    return SimpleNamespace(
        cookies=cookies or {},
        url=SimpleNamespace(path=path),
        client=SimpleNamespace(host=host),
        headers=headers or {},
    )


@pytest.fixture(autouse=True)
def setup_env():
    models.env = models.env_loader(username=TEST_USERNAME, password=TEST_PASSWORD)


# ---------------------------------------------------------------------------
# failed_auth_counter
# ---------------------------------------------------------------------------


def test_failed_auth_counter_creates_entry():
    utils.failed_auth_counter(make_mock_request(host="1.2.3.4"))
    assert failure_count("1.2.3.4") == 1


def test_failed_auth_counter_increments():
    request = make_mock_request(host="1.2.3.5")
    utils.failed_auth_counter(request)
    utils.failed_auth_counter(request)
    assert failure_count("1.2.3.5") == 2


def test_failed_auth_counter_keys_on_forwarded_client_ip():
    models.trusted_proxies = {"10.9.9.9"}
    request = make_mock_request(host="10.9.9.9", headers={"x-forwarded-for": "5.5.5.5"})
    utils.failed_auth_counter(request)
    assert failure_count("5.5.5.5") == 1
    assert failure_count("10.9.9.9") == 0


# ---------------------------------------------------------------------------
# client_ip
# ---------------------------------------------------------------------------


def test_client_ip_without_forwarded_header():
    assert utils.client_ip(make_mock_request(host="1.1.1.1")) == "1.1.1.1"


def test_client_ip_ignores_forwarded_header_from_untrusted_host():
    request = make_mock_request(host="1.1.1.1", headers={"x-forwarded-for": "6.6.6.6"})
    assert utils.client_ip(request) == "1.1.1.1"


def test_client_ip_uses_forwarded_header_from_trusted_proxy():
    models.trusted_proxies = {"10.0.0.5"}
    request = make_mock_request(host="10.0.0.5", headers={"x-forwarded-for": "7.7.7.7"})
    assert utils.client_ip(request) == "7.7.7.7"


def test_client_ip_skips_trusted_hops_and_spoofed_left_entries():
    models.trusted_proxies = {"10.0.0.5", "10.0.0.6"}
    request = make_mock_request(
        host="10.0.0.5", headers={"x-forwarded-for": "6.6.6.6, 7.7.7.7, 10.0.0.6"}
    )
    assert utils.client_ip(request) == "7.7.7.7"


def test_client_ip_falls_back_to_host_when_all_hops_trusted():
    models.trusted_proxies = {"10.0.0.5"}
    request = make_mock_request(host="10.0.0.5", headers={"x-forwarded-for": "10.0.0.5, "})
    assert utils.client_ip(request) == "10.0.0.5"


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
    assert failure_count("2.2.2.3") == 1

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


def test_verify_login_resets_failure_counter():
    host = "10.0.0.2"
    store.record_failure(host)
    store.record_failure(host)
    creds = build_credentials(TEST_USERNAME, TEST_PASSWORD)
    auth = HTTPAuthorizationCredentials(scheme="bearer", credentials=creds)
    utils.verify_login(authorization=auth, request=make_mock_request(host=host))
    assert failure_count(host) == 0


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
    store.add_session("valid-session-token", 300)
    utils.verify_session(
        api_request=make_mock_request(cookies={"session_token": "valid-session-token"})
    )


def test_verify_session_valid_from_any_host():
    """Sessions aren't bound to an IP, so another worker/proxy hop still validates."""
    store.add_session("shared-token", 300)
    for host in ("192.168.1.1", "172.16.0.9"):
        utils.verify_session(
            api_request=make_mock_request(
                cookies={"session_token": "shared-token"}, host=host
            )
        )


def test_verify_session_expired_redirects_to_session():
    store.add_session("expired-token", -1)
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(
            api_request=make_mock_request(cookies={"session_token": "expired-token"})
        )
    assert exc_info.value.destination == APIEndpoints.fastapi_session


def test_verify_session_no_cookie_redirects_to_login():
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(api_request=make_mock_request(cookies={}))
    assert exc_info.value.destination == APIEndpoints.fastapi_login


def test_verify_session_unknown_token_redirects_to_session():
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(
            api_request=make_mock_request(cookies={"session_token": "never-issued"})
        )
    assert exc_info.value.destination == APIEndpoints.fastapi_session


def test_verify_session_does_not_log_token(caplog):
    with pytest.raises(models.RedirectException):
        utils.verify_session(
            api_request=make_mock_request(cookies={"session_token": "secret-token"})
        )
    assert "secret-token" not in caplog.text


def test_verify_session_no_request_raises_400():
    with pytest.raises(HTTPException) as exc_info:
        utils.verify_session()
    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


def test_verify_session_websocket_valid():
    store.add_session("ws-valid-token", 300)
    ws = make_mock_websocket(cookies={"session_token": "ws-valid-token"})
    utils.verify_session(api_websocket=ws)  # should not raise


def test_verify_session_websocket_no_token():
    with pytest.raises(models.RedirectException) as exc_info:
        utils.verify_session(api_websocket=make_mock_websocket(cookies={}))
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


def test_clear_session_revokes_token():
    store.add_session("abc", 300)
    utils.clear_session("abc")
    assert not store.session_valid("abc")


def test_clear_session_unknown_token_does_not_raise():
    utils.clear_session("nonexistent-token-xyz")


def test_clear_session_none_is_noop():
    utils.clear_session(None)
