import logging
import secrets
from typing import Dict, List, NoReturn, Union

from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials

from fastapiauthenticator import enums, models, secure

LOGGER = logging.getLogger("uvicorn.default")


def failed_auth_counter(host: str) -> None:
    """Keeps track of failed login attempts from each host, and redirects if failed for 3 or more times.

    Args:
        host: Host header from the request.
    """
    try:
        models.ws_session.invalid[host] += 1
    except KeyError:
        models.ws_session.invalid[host] = 1
    if models.ws_session.invalid[host] >= 3:
        raise models.RedirectException(location=enums.APIEndpoints.fastapi_error)


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
    LOGGER.warning("Exception headers: %s", request.headers)
    LOGGER.warning("Exception cookies: %s", request.cookies)
    if request.url.path == enums.APIEndpoints.fastapi_verify_login:
        response = JSONResponse(
            content={"redirect_url": exception.location}, status_code=200
        )
    else:
        response = RedirectResponse(url=exception.location)
    if exception.detail:
        response.set_cookie(
            "detail", exception.detail.upper(), httponly=True, samesite="strict"
        )
    return response


def raise_error(host: str) -> NoReturn:
    """Raises a 401 Unauthorized error in case of bad credentials.

    Args:
        host: Host header from the request.
    """
    failed_auth_counter(host)
    LOGGER.error(
        "Incorrect username or password: %d",
        models.ws_session.invalid[host],
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers=None,
    )


def extract_credentials(
    authorization: HTTPAuthorizationCredentials, host: str
) -> List[str]:
    """Extract the credentials from ``Authorization`` headers and decode it before returning as a list of strings.

    Args:
        authorization: Authorization header from the request.
        host: Host header from the request.
    """
    if not authorization:
        raise_error(host)
    decoded_auth = secure.base64_decode(authorization.credentials)
    # convert hex to a string
    auth = secure.hex_decode(decoded_auth)
    return auth.split(",")


def verify_login(
    authorization: HTTPAuthorizationCredentials,
    host: str,
    env_username: str,
    env_password: str,
) -> Dict[str, Union[str, int]]:
    """Verifies authentication and generates session token for each user.

    Returns:
        Dict[str, str]:
        Returns a dictionary with the payload required to create the session token.
    """
    username, signature, timestamp = extract_credentials(authorization, host)
    if secrets.compare_digest(username, env_username):
        hex_user = secure.hex_encode(env_username)
        hex_pass = secure.hex_encode(env_password)
    else:
        LOGGER.warning("User '%s' not allowed", username)
        raise_error(host)
    message = f"{hex_user}{hex_pass}{timestamp}"
    expected_signature = secure.calculate_hash(message)
    if secrets.compare_digest(signature, expected_signature):
        models.ws_session.invalid[host] = 0
        key = secrets.token_urlsafe(64)
        models.ws_session.client_auth[host] = dict(
            username=username, token=key, timestamp=int(timestamp)
        )
        return models.ws_session.client_auth[host]
    raise_error(host)


def session_check(request: Request) -> None:
    """Check if the session is still valid.

    Args:
        request: Request object containing client information.

    Raises:
        HTTPException: If the session is invalid or expired.
    """
    stored_token = models.ws_session.client_auth.get(request.client.host, {}).get(
        "token"
    )
    session_token = request.cookies.get("session_token")
    if (
        stored_token
        and session_token
        and secrets.compare_digest(session_token, stored_token)
    ):
        LOGGER.info("Session is valid for host: %s", request.client.host)
        return
    raise models.RedirectException(
        location=enums.APIEndpoints.fastapi_session,
        detail="Session expired or invalid. Please log in again.",
    )


def clear_session(request: Request, response: HTMLResponse) -> HTMLResponse:
    """Clear the session token from the response.

    Args:
        request: FastAPI ``request`` object.
        response: FastAPI ``response`` object.

    Returns:
        HTMLResponse:
        Returns the response object with the session token cleared.
    """
    for cookie in request.cookies:
        # Deletes all cookies stored in current session
        LOGGER.info("Deleting cookie: '%s'", cookie)
        response.delete_cookie(cookie)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Authorization"] = ""
    return response
