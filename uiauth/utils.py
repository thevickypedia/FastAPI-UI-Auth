import secrets
from typing import List, NoReturn

from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.websockets import WebSocket

from uiauth import enums, logger, models, secure


def failed_auth_counter(request: Request) -> None:
    """Keeps track of failed login attempts from each host, and redirects if failed for 3 or more times.

    Args:
        request: Request object containing client information.
    """
    try:
        models.ws_session.invalid[request.client.host] += 1
    except KeyError:
        models.ws_session.invalid[request.client.host] = 1
    if models.ws_session.invalid[request.client.host] >= 3:
        raise models.RedirectException(destination=enums.APIEndpoints.fastapi_error)


def redirect_exception_handler(
    request: Request, exception: models.RedirectException
) -> JSONResponse | RedirectResponse:
    """Custom exception handler to handle redirect.

    Args:
        request: Takes the ``Request`` object as an argument.
        exception: Takes the ``RedirectException`` object inherited from ``Exception`` as an argument.

    Returns:
        JSONResponse:
        Returns the JSONResponse with content, status code and cookie.
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


def raise_error(request: Request) -> NoReturn:
    """Raises a 401 Unauthorized error in case of bad credentials.

    Args:
        request: Request object containing client information.
    """
    failed_auth_counter(request)
    logger.CUSTOM_LOGGER.error(
        "Incorrect username or password: %d",
        models.ws_session.invalid[request.client.host],
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers=None,
    )


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
    """Verifies authentication and generates session token for each user.

    Args:
        authorization: Authorization header from the request.
        request: Request object containing client information.

    Returns:
        str:
        Returns the session token.
    """
    if authorization:
        username, signature, timestamp = extract_credentials(authorization)
    else:
        raise_error(request)
    if secrets.compare_digest(username, models.env.username):
        hex_user = secure.hex_encode(models.env.username)
        hex_pass = secure.hex_encode(models.env.password)
    else:
        logger.CUSTOM_LOGGER.warning("User '%s' not allowed", models.env.username)
        raise_error(request)
    message = f"{hex_user}{hex_pass}{timestamp}"
    expected_signature = secure.calculate_hash(message)
    if secrets.compare_digest(signature, expected_signature):
        models.ws_session.invalid[request.client.host] = 0
        key = secrets.token_urlsafe(64)
        models.ws_session.client_auth[request.client.host] = key
        return key
    raise_error(request)


def verify_session(
    api_request: Request = None, api_websocket: WebSocket = None
) -> None:
    """Check if the session is still valid.

    Args:
        api_request: Request containing client information.
        api_websocket: WebSocket connection object.

    Raises:
        HTTPException: If the session is invalid or expired.
    """
    if api_request:
        request = api_request
    elif api_websocket:
        request = api_websocket
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request or WebSocket connection is required for session check.",
        )
    session_token = request.cookies.get("session_token")
    stored_token = models.ws_session.client_auth.get(request.client.host)
    if (
        stored_token
        and session_token
        and secrets.compare_digest(session_token, stored_token)
    ):
        logger.CUSTOM_LOGGER.info("Session is valid for host: %s", request.client.host)
        return
    elif not session_token:
        logger.CUSTOM_LOGGER.warning(
            "Session is invalid or expired for host: %s", request.client.host
        )
        raise models.RedirectException(
            source=request.url.path,
            destination=enums.APIEndpoints.fastapi_login,
        )
    else:
        logger.CUSTOM_LOGGER.warning(
            "Session token mismatch for host: %s. Expected: %s, Received: %s",
            request.client.host,
            stored_token,
            session_token,
        )
        raise models.RedirectException(
            source=request.url.path,
            destination=enums.APIEndpoints.fastapi_session,
        )


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


def clear_session(host: str) -> None:
    """Clear the session for the given host.

    Args:
        host: Host header from the request.
    """
    if models.ws_session.client_auth.get(host):
        models.ws_session.client_auth.pop(host)
        logger.CUSTOM_LOGGER.info("Session cleared for host: %s", host)
    else:
        logger.CUSTOM_LOGGER.warning("No session found for host: %s", host)
