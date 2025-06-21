import os
from threading import Timer
from typing import Callable, Dict, List

from fastapi import FastAPI
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapiauthenticator import endpoints, enums, models, utils

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
        secure_path: str = "/secure",
        session_timeout: int = 3600,
        username: str = os.environ.get("USERNAME"),
        password: str = os.environ.get("PASSWORD"),
    ):
        """Initialize the APIAuthenticator with the FastAPI app and secure function.

        Args:
            app: FastAPI application instance.
            secure_function: Function to be secured, which will be called after successful authentication.
            secure_path: API path for the secure function.
            username: Username for authentication, set via environment variable 'USERNAME'.
            password: Password for authentication, set via environment variable 'PASSWORD'.
        """
        assert all(
            (username, password)
        ), "Username and password must be set in environment variables 'USERNAME' and 'PASSWORD'."
        assert secure_function, "Secure function must be provided."
        if not secure_path.startswith("/"):
            secure_path = "/" + secure_path

        self.app = app
        self.secure_methods = secure_methods
        self.secure_function = secure_function
        self.secure_path = secure_path
        self.session_timeout = session_timeout

        # noinspection PyTypeChecker
        self.app.add_exception_handler(
            exc_class_or_status_code=models.RedirectException,
            handler=utils.redirect_exception_handler,
        )

        self.username = username
        self.password = password

    def verify_auth(
        self,
        request: Request,
        authorization: HTTPAuthorizationCredentials = Depends(BEARER_AUTH),
    ) -> Dict[str, str]:
        """Verify the authentication credentials and redirect to the secure route.

        Args:
            request: Request object containing client information.
            authorization: Authorization credentials from the request, provided by FastAPI's HTTPBearer.

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
        )
        self.app.routes.append(secure_route)
        # todo: Logging this might not be a bad idea
        Timer(
            function=self.app.routes.remove,
            args=(secure_route,),
            interval=self.session_timeout,
        ).start()
        return {"redirect_url": self.secure_path}

    def secure(self) -> None:
        """Create the login and verification routes for the APIAuthenticator."""
        login_route = APIRoute(
            path=enums.APIEndpoints.login, endpoint=endpoints.login, methods=["GET"]
        )
        error_route = APIRoute(
            path=enums.APIEndpoints.error, endpoint=endpoints.error, methods=["GET"]
        )
        session_route = APIRoute(
            path=enums.APIEndpoints.session, endpoint=endpoints.session, methods=["GET"]
        )
        verify_route = APIRoute(
            path=enums.APIEndpoints.verify_login,
            endpoint=self.verify_auth,
            methods=["GET", "POST"],
        )
        self.app.routes.extend([login_route, session_route, error_route, verify_route])
