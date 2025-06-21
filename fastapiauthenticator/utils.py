import pathlib
import secrets
from typing import Dict, List, NoReturn, Union

from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.logger import logger
from fastapi.requests import Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapiauthenticator import enums, models, secure

BEARER_AUTH = HTTPBearer()


def load_template() -> str:
    """Load the HTML template for the login page."""
    template_path = pathlib.Path(__file__).parent / "templates" / "index.html"
    with open(template_path, "r", encoding="utf-8") as file:
        return file.read()


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
        raise models.RedirectException(location="/error")


def redirect_exception_handler(
    request: Request, exception: models.RedirectException
) -> JSONResponse:
    """Custom exception handler to handle redirect.

    Args:
        request: Takes the ``Request`` object as an argument.
        exception: Takes the ``RedirectException`` object inherited from ``Exception`` as an argument.

    Returns:
        JSONResponse:
        Returns the JSONResponse with content, status code and cookie.
    """
    # LOGGER.debug("Exception headers: %s", request.headers)
    # LOGGER.debug("Exception cookies: %s", request.cookies)
    if request.url.path == enums.APIEndpoints.login:
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
    logger.error(
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
        logger.warning("User '%s' not allowed", username)
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
