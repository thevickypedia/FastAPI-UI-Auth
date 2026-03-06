import os
import pathlib
from typing import Dict, Iterable, Optional

from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")


class EnvConfig(BaseModel):
    """Model for environment configuration.

    >>> EnvConfig

    """

    username: str
    password: str


def get_cred(keys: Iterable[str], kwargs: Dict[str, str]) -> str | None:
    """Helper function to retrieve credentials from kwargs or environment variables.

    Args:
        keys: Iterable of keys to look for in kwargs and environment variables.
        kwargs: Key-value pairs to search for credentials, takes precedence over environment variables.

    Returns:
        str | None:
        The first found credential value or None if not found.
    """
    for key in keys:
        if value := kwargs.get(key) or os.getenv(key):
            return value
    return None


def env_loader(**kwargs) -> EnvConfig:
    """Loads environment variables into the EnvConfig model.

    See Also:
        - Tries to resolve username and password through kwargs.
        - Uses environment variables as fallback.

    Returns:
        EnvConfig:
        An instance of EnvConfig with loaded environment variables.
    """
    username = get_cred(["username", "USERNAME", "user", "USER"], kwargs)
    password = get_cred(["password", "PASSWORD", "pass", "PASS"], kwargs)
    return EnvConfig(username=username, password=password)


env = EnvConfig


class WSSession(BaseModel):
    """Object to store websocket session information.

    >>> WSSession

    """

    invalid: Dict[str, int] = Field(default_factory=dict)
    client_auth: Dict[str, Dict[str, str | int]] = Field(default_factory=dict)


class Fallback(BaseModel):
    """Object to store fallback information.

    >>> Fallback

    """

    button: str = Field(default="LOGIN", description="Title for the fallback button.")
    path: str = Field(
        default="/", description="Path to redirect when fallback button is clicked."
    )


class RedirectException(Exception):
    """Custom ``RedirectException`` raised within the API since HTTPException doesn't support returning HTML content.

    >>> RedirectException

    See Also:
        - RedirectException allows the API to redirect on demand in cases where returning is not a solution.
        - There are alternatives to raise HTML content as an exception but none work with our use-case with JavaScript.
        - This way of exception handling comes handy for many unexpected scenarios.

    References:
        https://fastapi.tiangolo.com/tutorial/handling-errors/#install-custom-exception-handlers
    """

    def __init__(self, destination: str, source: str = "/", detail: Optional[str] = ""):
        """Instantiates the ``RedirectException`` object with the required parameters.

        Args:
            source: Source from where the redirect is initiated.
            destination: Location to redirect.
            detail: Reason for redirect.
        """
        self.detail = detail
        self.source = source
        self.destination = destination


ws_session = WSSession()
fallback = Fallback()
