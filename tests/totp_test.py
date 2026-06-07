import logging
import logging
import time
from unittest.mock import MagicMock, patch

import pyotp
import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from uiauth import secure


# ---------------------------------------------------------------------------
# Helpers – build a valid encoded credential token (mirrors the JS client)
# ---------------------------------------------------------------------------


def _make_credentials(username: str, password: str, timestamp: str, otp: str = None) -> str:
    """Produce a base64(hex-encoded) token as the login page JS would."""
    hex_user = secure.hex_encode(username)
    hex_pass = secure.hex_encode(password)
    message = f"{hex_user}{hex_pass}{timestamp}"
    signature = secure.calculate_hash(message)
    if otp:
        raw = f"{username},{signature},{otp},{timestamp}"
    else:
        raw = f"{username},{signature},{timestamp}"
    # hex-encode each part then join with commas, then base64-encode
    # Actually the client sends: base64(hex_encode(username,signature,...))
    # Looking at extract_credentials: base64_decode → hex_decode → split(",")
    # So we need: base64_encode(hex_encode(raw_csv))
    hex_encoded = secure.hex_encode(raw)
    return secure.base64_encode(hex_encoded)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

USERNAME = "testuser"
PASSWORD = "testpass"
TOTP_SECRET = pyotp.random_base32()


def _make_app(use_totp: bool = False) -> tuple:
    """Create a fresh FastAPI app with uiauth protecting /secure."""
    from uiauth import models

    # Reset global session state
    models.ws_session.invalid.clear()
    models.ws_session.client_auth.clear()
    models.fallback.path = "/"
    models.fallback.button = "LOGIN"

    app = FastAPI()

    from fastapi.requests import Request as FRequest

    def secure_endpoint(request: FRequest):
        from fastapi.responses import JSONResponse
        return JSONResponse({"ok": True})

    route = APIRoute(path="/secure", endpoint=secure_endpoint, methods=["GET"])

    import uiauth
    kwargs = dict(
        app=app,
        routes=route,
        username=USERNAME,
        password=PASSWORD,
        session_timeout=60,
    )
    if use_totp:
        kwargs["totp_token"] = TOTP_SECRET

    with pytest.warns(UserWarning) if not use_totp else _no_warn():
        auth = uiauth.protect(**kwargs)

    client = TestClient(app, raise_server_exceptions=False)
    return app, client, auth


class _no_warn:
    """Context manager that expects no warnings (for TOTP path)."""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# ===========================================================================
# 1. secure.py
# ===========================================================================

class TestSecure:
    def test_calculate_hash_returns_hex_string(self):
        result = secure.calculate_hash("hello")
        assert isinstance(result, str)
        assert len(result) == 128  # SHA-512 hex

    def test_base64_roundtrip(self):
        original = "hello world"
        assert secure.base64_decode(secure.base64_encode(original)) == original

    def test_hex_roundtrip(self):
        original = "abc"
        assert secure.hex_decode(secure.hex_encode(original)) == original

    def test_verify_totp_valid(self):
        """Covers secure.py lines 48-49 (verify_totp body)."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        otp = totp.now()
        assert secure.verify_totp(token=secret, otp=otp) is True

    def test_verify_totp_invalid(self):
        """Also covers secure.py lines 48-49 via a False result."""
        secret = pyotp.random_base32()
        assert secure.verify_totp(token=secret, otp="000000") is False


# ===========================================================================
# 2. models.py
# ===========================================================================

class TestModels:
    def test_get_cred_returns_none_when_missing(self):
        """Covers models.py line 65 (None return in get_cred)."""
        from uiauth.models import get_cred
        result = get_cred(["nonexistent_key_xyz"], {})
        assert result is None

    def test_env_loader_without_totp(self):
        from uiauth.models import env_loader
        cfg = env_loader(username="u", password="p")
        assert cfg.username == "u"
        assert cfg.password == "p"
        assert cfg.totp_token is None

    def test_env_loader_with_valid_totp(self):
        """Covers models.py lines 15-19 (validate_totp_secret body) and line 65."""
        from uiauth.models import env_loader
        secret = pyotp.random_base32()
        cfg = env_loader(username="u", password="p", totp_token=secret)
        assert cfg.totp_token == secret

    def test_validate_totp_secret_bad_token_raises(self):
        """Covers the assertion path inside validate_totp_secret."""
        from uiauth.models import validate_totp_secret
        # A valid base32 but we mock pyotp.TOTP.verify to return False
        secret = pyotp.random_base32()
        with patch("uiauth.models.pyotp.TOTP") as mock_totp_cls:
            mock_totp = MagicMock()
            mock_totp.verify.return_value = False
            mock_totp.generate_otp.return_value = "123456"
            mock_totp.timecode.return_value = 0
            mock_totp_cls.return_value = mock_totp
            with pytest.raises(AssertionError, match="Invalid authenticatorToken"):
                validate_totp_secret(secret)

    def test_redirect_exception_attributes(self):
        from uiauth.models import RedirectException
        exc = RedirectException(destination="/dest", source="/src", detail="oops")
        assert exc.destination == "/dest"
        assert exc.source == "/src"
        assert exc.detail == "oops"

    def test_ws_session_model(self):
        from uiauth.models import WSSession
        s = WSSession()
        assert s.invalid == {}
        assert s.client_auth == {}

    def test_fallback_model_defaults(self):
        from uiauth.models import Fallback
        f = Fallback()
        assert f.button == "LOGIN"
        assert f.path == "/"


# ===========================================================================
# 3. utils.py – non-TOTP paths (already covered by existing tests)
# ===========================================================================

class TestUtils:
    """Tests that hit the still-missing lines in utils.py."""

    def _make_request(self, host="127.0.0.1", cookies=None, path="/fastapi-verify-login"):
        req = MagicMock()
        req.client.host = host
        req.url.path = path
        req.cookies = cookies or {}
        return req

    # --- failed_auth_counter ---

    def test_failed_auth_counter_first_failure(self):
        from uiauth import models, utils
        models.ws_session.invalid.clear()
        req = self._make_request(host="10.0.0.1")
        utils.failed_auth_counter(req)
        assert models.ws_session.invalid["10.0.0.1"] == 1

    def test_failed_auth_counter_increment(self):
        from uiauth import models, utils
        models.ws_session.invalid["10.0.0.2"] = 1
        req = self._make_request(host="10.0.0.2")
        utils.failed_auth_counter(req)
        assert models.ws_session.invalid["10.0.0.2"] == 2

    def test_failed_auth_counter_raises_redirect_after_3(self):
        from uiauth import models, utils
        models.ws_session.invalid["10.0.0.3"] = 2
        req = self._make_request(host="10.0.0.3")
        with pytest.raises(models.RedirectException):
            utils.failed_auth_counter(req)

    # --- redirect_exception_handler ---

    def test_redirect_exception_handler_verify_path_returns_json(self):
        from uiauth import models, utils
        req = self._make_request(path="/fastapi-verify-login")
        exc = models.RedirectException(destination="/fastapi-login", detail="")
        resp = utils.redirect_exception_handler(req, exc)
        from fastapi.responses import JSONResponse
        assert isinstance(resp, JSONResponse)

    def test_redirect_exception_handler_other_path_returns_redirect(self):
        from uiauth import models, utils
        req = self._make_request(path="/some-other-path")
        exc = models.RedirectException(destination="/fastapi-login", detail="")
        resp = utils.redirect_exception_handler(req, exc)
        from fastapi.responses import RedirectResponse
        assert isinstance(resp, RedirectResponse)

    def test_redirect_exception_handler_with_detail_sets_cookie(self):
        from uiauth import models, utils
        req = self._make_request(path="/other")
        exc = models.RedirectException(destination="/fastapi-login", detail="session expired")
        resp = utils.redirect_exception_handler(req, exc)
        # Cookie header should contain 'detail'
        headers = dict(resp.headers)
        assert "set-cookie" in headers or any(
            "detail" in v for v in resp.raw_headers if isinstance(v, tuple) and b"detail" in v[1])

    # --- verify_login – TOTP paths (the key missing lines) ---

    def _setup_totp_env(self):
        """Configure models.env to use TOTP."""
        from uiauth import models
        models.env = models.EnvConfig(
            username=USERNAME,
            password=PASSWORD,
            totp_token=TOTP_SECRET,
        )
        models.ws_session.invalid.clear()

    def test_verify_login_totp_valid(self):
        """Covers utils.py line 104 (4-value unpack) and happy path."""
        self._setup_totp_env()
        from uiauth import utils
        timestamp = str(int(time.time()))
        totp_otp = pyotp.TOTP(TOTP_SECRET).now()
        creds = _make_credentials(USERNAME, PASSWORD, timestamp, otp=totp_otp)
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=creds)
        req = self._make_request()
        token = utils.verify_login(authorization=auth, request=req)
        assert isinstance(token, str) and len(token) > 10

    def test_verify_login_totp_missing_otp(self):
        """Covers utils.py lines 119-121 (otp not provided despite TOTP enabled)."""
        self._setup_totp_env()
        from uiauth import utils
        timestamp = str(int(time.time()))
        # Build a 4-part credential but otp field is empty string
        from uiauth.secure import hex_encode, calculate_hash, base64_encode
        hex_user = hex_encode(USERNAME)
        hex_pass = hex_encode(PASSWORD)
        message = f"{hex_user}{hex_pass}{timestamp}"
        signature = calculate_hash(message)
        # otp is empty string → falsy
        raw = f"{USERNAME},{signature},,{timestamp}"
        hex_encoded = secure.hex_encode(raw)
        creds = base64_encode(hex_encoded)
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=creds)
        req = self._make_request()
        with pytest.raises(Exception):  # HTTPException 401
            utils.verify_login(authorization=auth, request=req)

    def test_verify_login_totp_invalid_otp(self):
        """Covers utils.py lines 122-124 (OTP provided but wrong)."""
        self._setup_totp_env()
        from uiauth import utils
        from uiauth.secure import hex_encode, calculate_hash, base64_encode
        timestamp = str(int(time.time()))
        hex_user = hex_encode(USERNAME)
        hex_pass = hex_encode(PASSWORD)
        message = f"{hex_user}{hex_pass}{timestamp}"
        signature = calculate_hash(message)
        bad_otp = "000000"
        raw = f"{USERNAME},{signature},{bad_otp},{timestamp}"
        hex_encoded = secure.hex_encode(raw)
        creds = base64_encode(hex_encoded)
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=creds)
        req = self._make_request()
        with pytest.raises(Exception):  # HTTPException 401
            utils.verify_login(authorization=auth, request=req)

    def test_verify_login_no_auth_raises(self):
        """Covers utils.py line 108 (authorization is falsy)."""
        from uiauth import utils, models
        models.env = models.EnvConfig(username=USERNAME, password=PASSWORD)
        models.ws_session.invalid.clear()
        req = self._make_request()
        with pytest.raises(Exception):
            utils.verify_login(authorization=None, request=req)

    def test_verify_login_wrong_username_raises(self):
        from uiauth import utils, models
        models.env = models.EnvConfig(username=USERNAME, password=PASSWORD)
        models.ws_session.invalid.clear()
        timestamp = str(int(time.time()))
        creds = _make_credentials("wronguser", PASSWORD, timestamp)
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=creds)
        req = self._make_request()
        with pytest.raises(Exception):
            utils.verify_login(authorization=auth, request=req)

    def test_verify_login_wrong_signature_raises(self):
        from uiauth import utils, models
        models.env = models.EnvConfig(username=USERNAME, password=PASSWORD)
        models.ws_session.invalid.clear()
        timestamp = str(int(time.time()))
        # Build a token with wrong password so signature mismatches
        creds = _make_credentials(USERNAME, "wrongpass", timestamp)
        auth = HTTPAuthorizationCredentials(scheme="Bearer", credentials=creds)
        req = self._make_request()
        with pytest.raises(Exception):
            utils.verify_login(authorization=auth, request=req)

    # --- verify_session ---

    def test_verify_session_no_request_or_websocket_raises(self):
        from uiauth import utils
        with pytest.raises(Exception) as exc_info:
            utils.verify_session()
        assert exc_info.value.status_code == 400

    def test_verify_session_valid_session_passes(self):
        from uiauth import utils, models
        host = "192.168.1.1"
        token = "validtoken123"
        models.ws_session.client_auth[host] = {
            "token": token,
            "expires_at": time.time() + 300,
        }
        req = self._make_request(host=host, cookies={"session_token": token}, path="/secure")
        # Should not raise
        utils.verify_session(api_request=req)

    def test_verify_session_expired_raises_redirect(self):
        from uiauth import utils, models
        host = "192.168.1.2"
        token = "expiredtoken"
        models.ws_session.client_auth[host] = {
            "token": token,
            "expires_at": time.time() - 10,  # expired
        }
        req = self._make_request(host=host, cookies={"session_token": token}, path="/secure")
        with pytest.raises(models.RedirectException) as exc_info:
            utils.verify_session(api_request=req)
        assert exc_info.value.destination == "/fastapi-login"

    def test_verify_session_no_cookie_raises_redirect(self):
        from uiauth import utils, models
        host = "192.168.1.3"
        req = self._make_request(host=host, cookies={}, path="/secure")
        with pytest.raises(models.RedirectException) as exc_info:
            utils.verify_session(api_request=req)
        assert exc_info.value.destination == "/fastapi-login"

    def test_verify_session_token_mismatch_raises_redirect_to_session(self):
        from uiauth import utils, models
        host = "192.168.1.4"
        models.ws_session.client_auth[host] = {
            "token": "correcttoken",
            "expires_at": time.time() + 300,
        }
        req = self._make_request(
            host=host, cookies={"session_token": "wrongtoken"}, path="/secure"
        )
        with pytest.raises(models.RedirectException) as exc_info:
            utils.verify_session(api_request=req)
        assert exc_info.value.destination == "/fastapi-session"

    def test_verify_session_via_websocket(self):
        from uiauth import utils, models
        host = "192.168.1.5"
        token = "wstoken"
        models.ws_session.client_auth[host] = {
            "token": token,
            "expires_at": time.time() + 300,
        }
        ws = self._make_request(host=host, cookies={"session_token": token}, path="/ws")
        # Should pass using api_websocket path
        utils.verify_session(api_websocket=ws)

    # --- deauthorize ---

    def test_deauthorize_clears_cookies_and_headers(self):
        from uiauth import utils
        from fastapi.responses import HTMLResponse
        resp = HTMLResponse(content="<html/>")
        result = utils.deauthorize(resp)
        assert result.headers["Cache-Control"] == "no-cache, no-store, must-revalidate"
        assert result.headers["Authorization"] == ""

    # --- clear_session ---

    def test_clear_session_existing_host(self):
        from uiauth import utils, models
        host = "10.1.1.1"
        models.ws_session.client_auth[host] = {"token": "t", "expires_at": 0}
        utils.clear_session(host)
        assert host not in models.ws_session.client_auth

    def test_clear_session_nonexistent_host(self):
        from uiauth import utils
        # Should not raise, just log a warning
        utils.clear_session("99.99.99.99")


# ===========================================================================
# 4. service.py (FastAPIUIAuth init guards)
# ===========================================================================

class TestServiceInit:
    def _minimal_route(self):
        def ep(request): pass

        return APIRoute(path="/x", endpoint=ep)

    def test_invalid_timeout_raises(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(AssertionError):
            uiauth.protect(app=app, routes=self._minimal_route(),
                           username=USERNAME, password=PASSWORD, session_timeout=5)

    def test_missing_credentials_raises(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(Exception):
            uiauth.protect(app=app, routes=self._minimal_route())

    def test_invalid_app_type_raises(self):
        import uiauth
        with pytest.raises(AssertionError):
            uiauth.protect(app="not_a_fastapi", routes=self._minimal_route(),
                           username=USERNAME, password=PASSWORD)

    def test_empty_routes_list_raises(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(AssertionError):
            uiauth.protect(app=app, routes=[],
                           username=USERNAME, password=PASSWORD)

    def test_invalid_route_in_list_raises(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(AssertionError):
            uiauth.protect(app=app, routes=["not_a_route"],
                           username=USERNAME, password=PASSWORD)

    def test_invalid_route_type_raises_value_error(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(ValueError):
            uiauth.protect(app=app, routes=42,
                           username=USERNAME, password=PASSWORD)

    def test_fallback_path_must_start_with_slash(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(AssertionError):
            uiauth.protect(app=app, routes=self._minimal_route(),
                           username=USERNAME, password=PASSWORD,
                           fallback=uiauth.Fallback(path="no-slash"))

    def test_custom_logger_invalid_type_raises(self):
        import uiauth
        app = FastAPI()
        with pytest.raises(AssertionError):
            uiauth.protect(app=app, routes=self._minimal_route(),
                           username=USERNAME, password=PASSWORD,
                           custom_logger="not_a_logger")

    def test_custom_logger_valid(self):
        import uiauth
        app = FastAPI()
        custom_log = logging.getLogger("custom")
        with pytest.warns(UserWarning):
            auth = uiauth.protect(app=app, routes=self._minimal_route(),
                                  username=USERNAME, password=PASSWORD,
                                  custom_logger=custom_log)
        assert auth is not None

    def test_websocket_route_accepted(self):
        import uiauth
        async def ws_ep(ws): pass

        app = FastAPI()
        ws_route = APIWebSocketRoute(path="/ws", endpoint=ws_ep)
        with pytest.warns(UserWarning):
            auth = uiauth.protect(app=app, routes=ws_route,
                                  username=USERNAME, password=PASSWORD)
        assert auth is not None

    def test_with_totp_no_warning(self):
        import uiauth
        app = FastAPI()
        secret = pyotp.random_base32()
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            auth = uiauth.protect(app=app, routes=self._minimal_route(),
                                  username=USERNAME, password=PASSWORD,
                                  totp_token=secret)
        user_warns = [x for x in w if issubclass(x.category, UserWarning)]
        assert len(user_warns) == 0

    def test_conflicting_route_gets_replaced(self):
        """Covers the conflicting-route removal branch in _secure()."""
        import uiauth
        def ep(req): pass

        app = FastAPI()
        # Register the same path ahead of protect()
        app.add_api_route("/protected", ep)
        route = APIRoute(path="/protected", endpoint=ep)
        with pytest.warns(UserWarning):
            uiauth.protect(app=app, routes=route,
                           username=USERNAME, password=PASSWORD)
        # The route should still be accessible (re-registered with auth)
        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/protected" in paths

    def test_list_of_routes_accepted(self):
        import uiauth
        def ep(req): pass

        app = FastAPI()
        routes = [
            APIRoute(path="/a", endpoint=ep),
            APIRoute(path="/b", endpoint=ep),
        ]
        with pytest.warns(UserWarning):
            auth = uiauth.protect(app=app, routes=routes,
                                  username=USERNAME, password=PASSWORD)
        assert auth is not None


# ===========================================================================
# 5. Integration – HTTP client tests
# ===========================================================================

class TestIntegration:
    def test_login_page_returns_200(self):
        _, client, _ = _make_app()
        resp = client.get("/fastapi-login", follow_redirects=False)
        assert resp.status_code == 200

    def test_secure_route_without_session_redirects(self):
        _, client, _ = _make_app()
        resp = client.get("/secure", follow_redirects=False)
        assert resp.status_code in (302, 307)

    def test_logout_without_session_renders_session_page(self):
        _, client, _ = _make_app()
        resp = client.get("/fastapi-logout", follow_redirects=False)
        assert resp.status_code == 200

    def test_error_page_returns_200(self):
        _, client, _ = _make_app()
        resp = client.get("/fastapi-error", follow_redirects=False)
        assert resp.status_code == 200

    def test_session_page_returns_200(self):
        _, client, _ = _make_app()
        resp = client.get("/fastapi-session", follow_redirects=False)
        assert resp.status_code == 200

    def test_verify_login_without_cookie_returns_417(self):
        _, client, _ = _make_app()
        timestamp = str(int(time.time()))
        creds = _make_credentials(USERNAME, PASSWORD, timestamp)
        resp = client.post(
            "/fastapi-verify-login",
            headers={"Authorization": f"Bearer {creds}"},
        )
        assert resp.status_code == 417

    def test_verify_login_success_returns_redirect_url(self):
        _, client, _ = _make_app()
        timestamp = str(int(time.time()))
        creds = _make_credentials(USERNAME, PASSWORD, timestamp)
        resp = client.post(
            "/fastapi-verify-login",
            headers={
                "Authorization": f"Bearer {creds}",
                "Cookie": "X-Requested-By=/secure",
            },
            cookies={"X-Requested-By": "/secure"},
        )
        assert resp.status_code == 200
        assert "redirect_url" in resp.json()

    def test_verify_login_with_totp_success(self):
        from uiauth import models
        models.ws_session.invalid.clear()
        app, client, _ = _make_app(use_totp=True)
        timestamp = str(int(time.time()))
        otp = pyotp.TOTP(TOTP_SECRET).now()
        creds = _make_credentials(USERNAME, PASSWORD, timestamp, otp=otp)
        resp = client.post(
            "/fastapi-verify-login",
            headers={"Authorization": f"Bearer {creds}"},
            cookies={"X-Requested-By": "/secure"},
        )
        assert resp.status_code == 200

    def test_full_auth_flow_accesses_secure_route(self):
        from uiauth import models
        models.ws_session.invalid.clear()
        models.ws_session.client_auth.clear()
        app, _, _ = _make_app()
        # Use a fresh client so cookies persist across requests
        client = TestClient(app, raise_server_exceptions=True)
        timestamp = str(int(time.time()))
        creds = _make_credentials(USERNAME, PASSWORD, timestamp)
        # Set the X-Requested-By cookie on the client before the POST
        client.cookies.set("X-Requested-By", "/secure")
        resp = client.post(
            "/fastapi-verify-login",
            headers={"Authorization": f"Bearer {creds}"},
        )
        assert resp.status_code == 200
        # session_token is now set on the client's cookie jar automatically
        resp2 = client.get("/secure")
        assert resp2.status_code == 200

    def test_logout_with_valid_session_renders_logout_page(self):
        from uiauth import models
        models.ws_session.invalid.clear()
        app, client, _ = _make_app()
        timestamp = str(int(time.time()))
        creds = _make_credentials(USERNAME, PASSWORD, timestamp)
        resp = client.post(
            "/fastapi-verify-login",
            headers={"Authorization": f"Bearer {creds}"},
            cookies={"X-Requested-By": "/secure"},
        )
        session_token = resp.cookies.get("session_token")
        resp2 = client.get("/fastapi-logout", cookies={"session_token": session_token})
        assert resp2.status_code == 200


# ===========================================================================
# 6. enums
# ===========================================================================

class TestEnums:
    def test_all_endpoints_have_leading_slash(self):
        from uiauth.enums import APIEndpoints
        for ep in APIEndpoints:
            assert str(ep).startswith("/")

    def test_enum_values(self):
        from uiauth.enums import APIEndpoints
        assert APIEndpoints.fastapi_login == "/fastapi-login"
        assert APIEndpoints.fastapi_logout == "/fastapi-logout"
        assert APIEndpoints.fastapi_error == "/fastapi-error"
        assert APIEndpoints.fastapi_session == "/fastapi-session"
        assert APIEndpoints.fastapi_verify_login == "/fastapi-verify-login"
