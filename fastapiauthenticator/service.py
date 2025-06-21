import os
from typing import Callable, Dict

import jinja2
from fastapi import FastAPI
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from fastapiauthenticator import utils
from fastapiauthenticator.version import version

BEARER_AUTH = HTTPBearer()

# todo: Include session management


class Authenticator:
    """Authenticator is a FastAPI integration that provides authentication for secure routes.

    >>> Authenticator

    """

    def __init__(
        self,
        app: FastAPI,
        secure_function: Callable = None,
        secure_path: str = "/secure",
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
        self.template = utils.load_template()
        self.secure_function = secure_function
        self.secure_path = secure_path

        self.username = username
        self.password = password

        self.login_path: str = "/login"
        self.verify_path: str = "/verify-login"

    def send_auth(self) -> HTMLResponse:
        """Render the login page with the verification path and version.

        Returns:
            HTMLResponse:
            Rendered HTML response for the login page.
        """
        rendered = jinja2.Template(self.template).render(
            signin=self.verify_path, version=version
        )
        return HTMLResponse(content=rendered, status_code=200)

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
            methods=["GET", "POST"],
        )
        self.app.routes.append(secure_route)
        return {"redirect_url": self.secure_path}

    def secure(self) -> None:
        """Create the login and verification routes for the APIAuthenticator."""
        login_route = APIRoute(
            path=self.login_path, endpoint=self.send_auth, methods=["GET"]
        )
        verify_route = APIRoute(
            path=self.verify_path, endpoint=self.verify_auth, methods=["GET", "POST"]
        )
        self.app.routes.extend([login_route, verify_route])
