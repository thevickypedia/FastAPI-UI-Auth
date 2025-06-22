import logging
import os
from threading import Timer
from typing import Callable, Dict, List

import dotenv
from fastapi import FastAPI
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.responses import Response
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapiauthenticator import endpoints, enums, models, utils

dotenv.load_dotenv(dotenv_path=dotenv.find_dotenv(), override=True)
LOGGER = logging.getLogger("uvicorn.default")
BEARER_AUTH = HTTPBearer()


# noinspection PyDefaultArgument
class Authenticator:
    """Authenticator is a FastAPI integration that provides authentication for secure routes.

    >>> Authenticator

    """

    def __init__(
        self,
        app: FastAPI,
        secure_function: Callable = None,
        secure_methods: List[str] = ["GET", "POST"],
        secure_path: str = enums.APIEndpoints.fastapi_secure,
        username: str = os.environ.get("USERNAME"),
        password: str = os.environ.get("PASSWORD"),
        session_timeout: int = 3600,
        fallback_button: str = models.fallback.button,
        fallback_path: str = models.fallback.path,
    ):
        """Initialize the APIAuthenticator with the FastAPI app and secure function.

        Args:
            app: FastAPI application instance to which the authenticator will be added.
            secure_function: Function to be called for secure routes after authentication.
            secure_methods: List of HTTP methods that the secure function will handle.
            secure_path: Path for the secure route, must start with '/'.
            username: Username for authentication, can be set via environment variable 'USERNAME'.
            password: Password for authentication, can be set via environment variable 'PASSWORD'.
            session_timeout: Duration in seconds after which the session expires.
            fallback_button: Title for the fallback button, defaults to "LOGIN".
            fallback_path: Fallback path to redirect to in case of session timeout or invalid session.
        """
        assert all((username, password)), "'username' and 'password' are mandatory."
        assert secure_function, "Secure function must be provided."
        assert secure_path.startswith("/"), "Secure path must start with '/'"
        assert fallback_path.startswith("/"), "Fallback path must start with '/'"

        self.app = app
        self.secure_methods = secure_methods
        self.secure_function = secure_function
        self.secure_path = secure_path
        self.session_timeout = session_timeout
        models.fallback.path = fallback_path
        models.fallback.button = fallback_button

        # noinspection PyTypeChecker
        self.app.add_exception_handler(
            exc_class_or_status_code=models.RedirectException,
            handler=utils.redirect_exception_handler,
        )

        self.username = username
        self.password = password

        self._secure()

    def _verify_auth(
        self,
        request: Request,
        authorization: HTTPAuthorizationCredentials = Depends(BEARER_AUTH),
        response: Response = None,
    ) -> Dict[str, str]:
        """Verify the authentication credentials and redirect to the secure route.

        Args:
            request: Request object containing client information.
            authorization: Authorization credentials from the request, provided by FastAPI's HTTPBearer.
            response: Response object containing the response from FastAPI's HTTPBearer.

        Returns:
            Dict[str, str]:
            A dictionary containing the redirect URL to the secure path.
        """
        utils.verify_login(
            authorization=authorization,
            host=request.client.host,
            env_username=self.username,
            env_password=self.password,
        )
        secure_route = APIRoute(
            path=self.secure_path,
            endpoint=self.secure_function,
            methods=self.secure_methods,
            dependencies=[Depends(utils.session_check)],
        )
        self.app.routes.append(secure_route)
        LOGGER.info("Setting session timeout for %s seconds", self.session_timeout)
        self._handle_session(
            response=response, request=request, secure_route=secure_route
        )
        return {"redirect_url": self.secure_path}

    def _setup_session_route(self, secure_route: APIRoute) -> None:
        """Removes the secure route and adds a routing logic for invalid sessions.

        Args:
            secure_route: Secure route to be removed from the app after the session timeout.
        """
        LOGGER.info("Session expired, removing secure route: %s", secure_route.path)
        self.app.routes.remove(secure_route)
        LOGGER.info(
            "Adding session route to handle expired sessions at %s", self.secure_path
        )
        self.app.routes.append(
            APIRoute(
                path=self.secure_path,
                endpoint=endpoints.session,
                methods=["GET"],
            )
        )

    def _handle_session(
        self, response: Response, request: Request, secure_route: APIRoute
    ) -> None:
        """Handle session management by setting a cookie and scheduling session removal.

        Args:
            response: Response object to set the session cookie.
            request: Request object containing client information.
            secure_route: Secure route to be removed from the app after the session timeout.
        """
        # Remove the secure route after the session timeout - backend
        Timer(
            function=self._setup_session_route,
            args=(secure_route,),
            interval=self.session_timeout,
        ).start()
        # Set the max age in session cookie to session timeout - frontend
        response.set_cookie(
            key="session_token",
            value=models.ws_session.client_auth[request.client.host].get("token"),
            httponly=True,
            samesite="strict",
            max_age=self.session_timeout,
        )

    def _secure(self) -> None:
        """Create the login and verification routes for the APIAuthenticator."""
        login_route = APIRoute(
            path=enums.APIEndpoints.fastapi_login,
            endpoint=endpoints.login,
            methods=["GET"],
        )
        error_route = APIRoute(
            path=enums.APIEndpoints.fastapi_error,
            endpoint=endpoints.error,
            methods=["GET"],
        )
        session_route = APIRoute(
            path=enums.APIEndpoints.fastapi_session,
            endpoint=endpoints.session,
            methods=["GET"],
        )
        verify_route = APIRoute(
            path=enums.APIEndpoints.fastapi_verify_login,
            endpoint=self._verify_auth,
            methods=["POST"],
        )
        self.app.routes.extend([login_route, session_route, error_route, verify_route])
