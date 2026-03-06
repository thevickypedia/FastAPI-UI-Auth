import logging
import time
from typing import Dict, List

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from uiauth import endpoints, enums, logger, models, utils

BEARER_AUTH = HTTPBearer()


# noinspection PyDefaultArgument
class FastAPIUIAuth:
    """FastAPIUIAuth is a FastAPI integration that provides authentication for secure routes.

    >>> FastAPIUIAuth

    """

    def __init__(
        self,
        app: FastAPI,
        routes: APIRoute | APIWebSocketRoute | List[APIRoute] | List[APIWebSocketRoute],
        timeout: int = 300,
        username: str = None,
        password: str = None,
        fallback_button: str = models.fallback.button,
        fallback_path: str = models.fallback.path,
        custom_logger: logging.Logger = None,
    ):
        """Initialize the APIAuthenticator with the FastAPI app and secure function.

        Args:
            app: FastAPI application instance to which the authenticator will be added.
            routes: APIRoute or APIWebSocketRoute instance(s) representing the routes to be protected by authentication.
            timeout: Session timeout in seconds, default is 300 seconds (5 minutes).
            username: Username for authentication, can be set via environment variable 'USERNAME'.
            password: Password for authentication, can be set via environment variable 'PASSWORD'.
            fallback_button: Title for the fallback button, defaults to "LOGIN".
            fallback_path: Fallback path to redirect to in case of session timeout or invalid session.
            custom_logger: Custom logger instance, defaults to the custom logger.
        """
        assert (
            isinstance(timeout, int) and timeout > 29
        ), "Timeout must be an integer at least 30 seconds"
        models.env = models.env_loader(username=username, password=password)
        assert (
            models.env.username and models.env.password
        ), "Username and password must be provided either as arguments or environment variables"
        assert isinstance(app, FastAPI), "App must be an instance of FastAPI"

        self.app = app

        if isinstance(routes, list):
            assert len(routes) > 0, "No endpoints to register"
            for route in routes:
                assert isinstance(route, APIRoute) or isinstance(
                    route, APIWebSocketRoute
                ), f"{route} must be an instance of APIRoute or APIWebSocketRoute"
            self.routes = routes
        elif isinstance(routes, APIRoute) or isinstance(routes, APIWebSocketRoute):
            self.routes = [routes]
        else:
            raise ValueError(
                "Routes must be an instance of APIRoute or APIWebSocketRoute or a list of them"
            )

        assert fallback_path.startswith("/"), "Fallback path must start with '/'"
        models.fallback.path = fallback_path
        models.fallback.button = fallback_button

        # noinspection PyTypeChecker
        self.app.add_exception_handler(
            exc_class_or_status_code=models.RedirectException,
            handler=utils.redirect_exception_handler,
        )

        if custom_logger:
            assert isinstance(
                custom_logger, logging.Logger
            ), "Custom logger must be an instance of logging.Logger"
            logger.CUSTOM_LOGGER = custom_logger
        self.timeout = timeout

        self._secure()
        logger.CUSTOM_LOGGER.debug("Endpoints registered: %s", len(self.routes))

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
        session_token = utils.verify_login(
            authorization=authorization,
            request=request,
        )
        if destination := request.cookies.get("X-Requested-By"):
            logger.CUSTOM_LOGGER.info(
                "Setting session timeout for %s seconds", self.timeout
            )
            # Set session_token cookie with a timeout, to be used for session validation when redirected
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=True,
                samesite="strict",
                max_age=self.timeout,
            )
            models.ws_session.client_auth[request.client.host] = {
                "token": session_token,
                "expires_at": time.time() + self.timeout,
            }
            response.delete_cookie(key="X-Requested-By")
            return {"redirect_url": destination}
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
        logout_route = APIRoute(
            path=enums.APIEndpoints.fastapi_logout,
            endpoint=endpoints.logout,
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
        protected_paths = {route.path for route in self.routes}
        conflicting = [
            route
            for route in self.app.routes
            if isinstance(route, (APIRoute, APIWebSocketRoute))
            and route.path in protected_paths
        ]
        for existing in conflicting:
            logger.CUSTOM_LOGGER.warning(
                "Route %s already registered in the app, removing and re-registering with authentication",
                existing.path,
            )
            self.app.routes.remove(existing)
        for route in self.routes:
            # WebSocket routes will not have a login path, they will be protected by session check
            if isinstance(route, APIWebSocketRoute):
                secure_route = APIWebSocketRoute(
                    path=route.path,
                    endpoint=route.endpoint,
                    dependencies=list(route.dependencies)
                    + [Depends(utils.verify_session)],
                )
            else:
                secure_route = APIRoute(
                    path=route.path,
                    endpoint=route.endpoint,
                    methods=list(route.methods) if route.methods else ["GET"],
                    dependencies=list(route.dependencies)
                    + [Depends(utils.verify_session)],
                )
            self.app.routes.append(secure_route)
        self.app.routes.extend(
            [login_route, logout_route, session_route, verify_route, error_route]
        )
