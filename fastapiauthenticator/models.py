import pathlib
from typing import Callable, Dict, List, Optional, Type

from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, PositiveInt

from fastapiauthenticator.enums import APIMethods

templates = Jinja2Templates(directory=pathlib.Path(__file__).parent / "templates")


class Params(BaseModel):
    """Parameters for the Authenticator class.

    >>> Params

    Attributes:
        function: Function to be called for secure routes after authentication.
        methods: List of HTTP methods that the secure function will handle.
        route: Type of route to be used for secure routes, either APIWebSocketRoute or APIRoute.
        path: Path for the secure route, must start with '/'.
    """

    function: Callable
    methods: List[APIMethods] = None
    route: Type[APIWebSocketRoute] | Type[APIRoute]
    path: str = Field(
        pattern="^/.*$", description="Path for the secure route, must start with '/'"
    )
    timeout: PositiveInt = Field(
        ge=0, default=300, description="Session timeout in seconds."
    )


class WSSession(BaseModel):
    """Object to store websocket session information.

    >>> WSSession

    """

    invalid: Dict[str, int] = Field(default_factory=dict)
    client_auth: Dict[str, Dict[str, int]] = Field(default_factory=dict)


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

    def __init__(self, location: str, detail: Optional[str] = ""):
        """Instantiates the ``RedirectException`` object with the required parameters.

        Args:
            location: Location for redirect.
            detail: Reason for redirect.
        """
        self.location = location
        self.detail = detail


ws_session = WSSession()
fallback = Fallback()
