import pathlib
import secrets
from typing import Dict, List, NoReturn, Union

from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.logger import logger
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from pyapiauthenticator import secure
from pyapiauthenticator.fastapi import models

BEARER_AUTH = HTTPBearer()


def load_template() -> str:
    """Load the HTML template for the login page."""
    template_path = pathlib.Path(__file__).parent.parent / "templates" / "index.html"
    with open(template_path, "r", encoding="utf-8") as file:
        return file.read()


def raise_error(host: str) -> NoReturn:
    """Raises a 401 Unauthorized error in case of bad credentials.

    Args:
        host: Host header from the request.
    """
    # failed_auth_counter(host)
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
