import secrets
from typing import List, NoReturn

from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.websockets import WebSocket

from uiauth import enums, logger, models, secure, store


def client_ip(request: Request | WebSocket) -> str:
    """Resolve the client IP, honoring X-Forwarded-For only when set by a trusted proxy."""
    host = request.client.host
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and host in models.trusted_proxies:
        # walk from the right; the first hop that isn't a trusted proxy is the client
        for hop in reversed([h.strip() for h in forwarded.split(",")]):
            if hop and hop not in models.trusted_proxies:
                return hop
    return host


def failed_auth_counter(request: Request) -> None:
    """Track failed logins per client IP (shared across workers) and redirect after 3."""
    if store.record_failure(client_ip(request)) >= 3:
        raise models.RedirectException(destination=enums.APIEndpoints.fastapi_error)


def raise_error(request: Request) -> NoReturn:
    """Raises a 401 Unauthorized error in case of bad credentials."""
    failed_auth_counter(request)
    logger.CUSTOM_LOGGER.error("Invalid credentials from %s", client_ip(request))
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers=None,
    )


def redirect_exception_handler(
    request: Request, exception: models.RedirectException
) -> JSONResponse | RedirectResponse:
    """Custom exception handler to handle redirect.

    Args:
        request: Takes the ``Request`` object as an argument.
        exception: Takes the ``RedirectException`` object inherited from ``Exception`` as an argument.

    Returns:
        JSONResponse:
        Returns the JSONResponse with content, status-code and cookie.
    """
    if request.url.path == enums.APIEndpoints.fastapi_verify_login:
        response = JSONResponse(content={"redirect_url": exception.destination})
    else:
        response = RedirectResponse(url=exception.destination)
    if exception.detail:
        response.set_cookie(
            "detail", exception.detail.upper(), httponly=True, samesite="strict"
        )
    response.set_cookie(
        "X-Requested-By", exception.source, httponly=True, samesite="strict"
    )
    return response


def extract_credentials(authorization: HTTPAuthorizationCredentials) -> List[str]:
    """Extract the credentials from ``Authorization`` headers and decode it before returning as a list of strings.

    Args:
        authorization: Authorization header from the request.
    """
    decoded_auth = secure.base64_decode(authorization.credentials)
    # convert hex to a string
    auth = secure.hex_decode(decoded_auth)
    return auth.split(",")


def verify_login(
    authorization: HTTPAuthorizationCredentials,
    request: Request,
) -> str | NoReturn:
    """Verifies authentication and generates a session token for each user.

    Args:
        authorization: Authorization header from the request.
        request: ``Request`` object containing client information.

    Returns:
        str:
        Returns the session token.
    """
    otp = None
    if authorization:
        # Raises ValueError if the credentials are not in the expected format
        if models.env.totp_token:
            username, signature, otp, timestamp = extract_credentials(authorization)
        else:
            username, signature, timestamp = extract_credentials(authorization)
    else:
        raise_error(request)
    if secrets.compare_digest(username, models.env.username):
        hex_user = secure.hex_encode(models.env.username)
        hex_pass = secure.hex_encode(models.env.password)
    else:
        logger.CUSTOM_LOGGER.warning("User '%s' not allowed", username)
        raise_error(request)
    message = f"{hex_user}{hex_pass}{timestamp}"
    expected_signature = secure.calculate_hash(message)
    if secrets.compare_digest(signature, expected_signature):
        if models.env.totp_token:
            if not otp:
                logger.CUSTOM_LOGGER.warning("TOTP token is required but not provided")
                raise_error(request)
            if not secure.verify_totp(token=models.env.totp_token, otp=otp):
                logger.CUSTOM_LOGGER.warning("Invalid TOTP token provided")
                raise_error(request)
        store.reset_failures(client_ip(request))
        key = secrets.token_urlsafe(64)
        return key
    raise_error(request)


# noinspection bad-assignment
def verify_session(
    api_request: Request = None, api_websocket: WebSocket = None
) -> None:
    """Check the session cookie against the shared store.

    Raises:
        RedirectException: If the session is missing, invalid or expired.
    """
    request = api_request if api_request is not None else api_websocket
    if request is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request or WebSocket connection is required for session check.",
        )
    session_token = request.cookies.get("session_token")
    if session_token and store.session_valid(session_token):
        logger.CUSTOM_LOGGER.debug("Session is valid; requesting: %s", request.url.path)
        return
    if not session_token:
        logger.CUSTOM_LOGGER.warning(
            "No session cookie for host: %s; requesting: %s",
            client_ip(request),
            request.url.path,
        )
        raise models.RedirectException(
            source=request.url.path,
            destination=enums.APIEndpoints.fastapi_login,
        )
    # cookie present but unknown/expired in the store (tokens are never logged)
    logger.CUSTOM_LOGGER.warning(
        "Invalid or expired session for host: %s; requesting: %s",
        client_ip(request),
        request.url.path,
    )
    raise models.RedirectException(
        source=request.url.path,
        destination=enums.APIEndpoints.fastapi_session,
    )


def clear_session(token: str | None) -> None:
    """Revoke a session server-side."""
    if token:
        store.delete_session(token)
        logger.CUSTOM_LOGGER.info("Session revoked")


def deauthorize(response: HTMLResponse) -> HTMLResponse:
    """Remove authorization headers and clear session token from the response.

    Args:
        response: FastAPI ``response`` object.

    Returns:
        HTMLResponse:
        Returns the response object with the session token cleared.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Authorization"] = ""
    response.delete_cookie("session_token")
    return response
