import inspect
import logging
import time
import warnings
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
        routes: APIRoute | APIWebSocketRoute | List[APIRoute | APIWebSocketRoute],
        username: str | None = None,
        password: str | None = None,
        totp_token: str | None = None,
        session_timeout: int = 300,
        fallback: models.Fallback | None = None,
        custom_logger: logging.Logger | None = None,
    ):
        """Initialize the APIAuthenticator with the FastAPI app and secure function.

        Args:
            app: FastAPI application instance to which the authenticator will be added.
            routes: APIRoute or APIWebSocketRoute instance(s) representing the routes to be protected by authentication.
            username: Username for authentication, can be set via environment variable 'USERNAME'.
            password: Password for authentication, can be set via environment variable 'PASSWORD'.
            totp_token: TOTP token for 2FA, can be set via environment variable 'TOTP_TOKEN'.
            session_timeout: Session timeout in seconds, default is 300 seconds (5 minutes).
            fallback: Fallback configuration for redirection, that takes a 'button' and 'path' as arguments.
            custom_logger: Custom logger instance, defaults to the custom logger.
        """
        # TODO:
        #   1. Add a reset option in the UI to refresh page after cookie expires or session becomes invalid
        #   2. Add support for multiple MFA methods (email, Telegram, etc.) and allow create models for it
        assert (
            isinstance(session_timeout, int) and 29 < session_timeout < 86_401
        ), "Timeout must be an integer between 30 seconds and 24 hours (86_400 seconds)"
        models.env = models.env_loader(
            username=username, password=password, totp_token=totp_token
        )
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

        if fallback:
            assert fallback.path.startswith("/"), "Fallback path must start with '/'"
            models.fallback = fallback
        else:
            models.fallback = models.Fallback()

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
        self.session_timeout = session_timeout

        self._secure()
        logger.CUSTOM_LOGGER.debug("Endpoints registered: %s", len(self.routes))
        if not models.env.totp_token:
            warning = "No TOTP token provided, skipping 2FA. This is not recommended for production use."
            logger.CUSTOM_LOGGER.warning(warning)
            warnings.warn(warning, UserWarning)

    def _verify_auth(
        self,
        request: Request,
        response: Response,
        authorization: HTTPAuthorizationCredentials = Depends(BEARER_AUTH),
    ) -> Dict[str, str]:
        """Verify the authentication credentials and redirect to the secure route.

        Args:
            request: Request object containing client information.
            response: Response object containing the response from FastAPI's HTTPBearer.
            authorization: Authorization credentials from the request, provided by FastAPI's HTTPBearer.

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
                "Setting session timeout for %s seconds", self.session_timeout
            )
            # Set session_token cookie with a timeout, to be used for session validation when redirected
            response.set_cookie(
                key="session_token",
                value=session_token,
                httponly=True,
                samesite="strict",
                max_age=self.session_timeout,
            )
            models.ws_session.client_auth[request.client.host] = {
                "token": session_token,
                "expires_at": time.time() + self.session_timeout,
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
            include_in_schema=False,
        )
        logout_route = APIRoute(
            path=enums.APIEndpoints.fastapi_logout,
            endpoint=endpoints.logout,
            methods=["GET"],
            include_in_schema=False,
        )
        error_route = APIRoute(
            path=enums.APIEndpoints.fastapi_error,
            endpoint=endpoints.error,
            methods=["GET"],
            include_in_schema=False,
        )
        session_route = APIRoute(
            path=enums.APIEndpoints.fastapi_session,
            endpoint=endpoints.session,
            methods=["GET"],
            include_in_schema=False,
        )
        verify_route = APIRoute(
            path=enums.APIEndpoints.fastapi_verify_login,
            endpoint=self._verify_auth,
            methods=["POST"],
            include_in_schema=False,
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
            kwargs = {
                name: getattr(route, name)
                for name in inspect.signature(route.__class__.__init__).parameters
                if name != "self" and hasattr(route, name)
            }
            kwargs["dependencies"] = list(route.dependencies) + [
                Depends(utils.verify_session)
            ]
            secure_route = route.__class__(**kwargs)
            self.app.routes.append(secure_route)
        self.app.routes.extend(
            [login_route, logout_route, session_route, verify_route, error_route]
        )
