import logging
import os
from threading import Timer
from typing import Dict, List

import dotenv
from fastapi import status
from fastapi.applications import FastAPI
from fastapi.exceptions import HTTPException
from fastapi.params import Depends
from fastapi.requests import Request
from fastapi.responses import Response
from fastapi.routing import APIRoute, APIWebSocketRoute
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
        params: models.Parameters | List[models.Parameters],
        timeout: int = 300,
        username: str = os.environ.get("USERNAME"),
        password: str = os.environ.get("PASSWORD"),
        fallback_button: str = models.fallback.button,
        fallback_path: str = models.fallback.path,
    ):
        """Initialize the APIAuthenticator with the FastAPI app and secure function.

        Args:
            app: FastAPI application instance to which the authenticator will be added.
            params: Parameters for the secure routes, can be a single `Parameters` object or a list of `Parameters`.
            timeout: Session timeout in seconds, default is 300 seconds (5 minutes).
            username: Username for authentication, can be set via environment variable 'USERNAME'.
            password: Password for authentication, can be set via environment variable 'PASSWORD'.
            fallback_button: Title for the fallback button, defaults to "LOGIN".
            fallback_path: Fallback path to redirect to in case of session timeout or invalid session.
        """
        assert all((username, password)), "'username' and 'password' are mandatory."
        assert fallback_path.startswith("/"), "Fallback path must start with '/'"

        self.app = app

        if isinstance(params, list):
            self.params = params
        elif isinstance(params, models.Parameters):
            self.params = [params]

        self.route_map: Dict[str, models.Parameters] = {
            param.path: param for param in self.params if param.route is APIRoute
        }

        models.fallback.path = fallback_path
        models.fallback.button = fallback_button

        # noinspection PyTypeChecker
        self.app.add_exception_handler(
            exc_class_or_status_code=models.RedirectException,
            handler=utils.redirect_exception_handler,
        )

        self.username = username
        self.password = password
        self.timeout = timeout

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
            request=request,
            env_username=self.username,
            env_password=self.password,
        )
        destination = request.cookies.get("X-Requested-By")
        if parameter := self.route_map.get(destination):
            LOGGER.info("Setting session timeout for %s seconds", self.timeout)
            # Set session_token cookie with a timeout, to be used for session validation when redirected
            response.set_cookie(
                key="session_token",
                value=models.ws_session.client_auth[request.client.host].get("token"),
                httponly=True,
                samesite="strict",
                max_age=self.timeout,
            )
            response.delete_cookie(key="X-Requested-By")
            Timer(
                function=utils.clear_session,
                args=(request.client.host,),
                interval=self.timeout,
            ).start()
            return {"redirect_url": parameter.path}
        raise HTTPException(
            status_code=status.HTTP_417_EXPECTATION_FAILED,
            detail="Unable to find secure route for the requested path.\n"
            "Missing cookie: 'X-Requested-By'\n"
            "Reload the source page to authenticate.",
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
        for param in self.params:
            if param.route is APIWebSocketRoute:
                # WebSocket routes will not have a login path, they will be protected by session check
                secure_route = APIWebSocketRoute(
                    path=param.path,
                    endpoint=param.function,
                    dependencies=[Depends(utils.session_check)],
                )
            else:
                secure_route = APIRoute(
                    path=param.path,
                    endpoint=param.function,
                    methods=["GET"],
                    dependencies=[Depends(utils.session_check)],
                )
            self.app.routes.append(secure_route)
        self.app.routes.extend([login_route, session_route, verify_route, error_route])
