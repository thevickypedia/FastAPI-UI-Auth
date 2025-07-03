import os
import pathlib
from typing import Callable, Dict, List, Optional, Type

from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from uiauth.enums import APIMethods

templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")


def get_env(keys: List[str], default: Optional[str] = None) -> Optional[str]:
    """Get environment variable value.

    Args:
        keys: List of environment variable names to check.
        default: Default value if the environment variable is not set.

    Returns:
        Value of the environment variable or default value.
    """
    for key in keys:
        if value := os.getenv(key):
            return value
        if value := os.getenv(key.upper()):
            return value
        if value := os.getenv(key.lower()):
            return value
    return default


class EnvConfig(BaseModel):
    """Configuration for environment variables."""

    username: str
    password: str

    # noinspection PyMethodParameters
    @field_validator("username", "password", mode="before")
    def load_user(cls, key: str, field: ValidationInfo) -> str | None:
        """Load environment variables into the configuration.

        Args:
            key: Environment variable key to check.
            field: Field information for validation.

        See Also:
            - This method checks if the environment variable is set and returns its value.
            - If the key is not set, it attempts to get the value from the environment using a helper function.

        Returns:
            str | None:
            Value of the environment variable or None if not set.
        """
        if not key:
            return get_env([field.field_name, field.field_name[:4]])


env = EnvConfig


class Parameters(BaseModel):
    """Parameters for the Authenticator class.

    >>> Parameters

    Attributes:
        path: Path for the secure route, must start with '/'.
        function: Function to be called for secure routes after authentication.
        methods: List of HTTP methods that the secure function will handle.
        route: Type of route to be used for secure routes, either APIWebSocketRoute or APIRoute.
    """

    path: str = Field(
        pattern="^/.*$", description="Path for the secure route, must start with '/'"
    )
    function: Callable
    methods: List[APIMethods] = [APIMethods.GET]
    route: Type[APIWebSocketRoute] | Type[APIRoute] = APIRoute


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
