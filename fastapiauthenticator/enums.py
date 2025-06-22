from enum import StrEnum


class APIEndpoints(StrEnum):
    """API endpoints for all the routes.

    >>> APIEndpoints

    """

    fastapi_error = "/fastapi-error"
    fastapi_login = "/fastapi-login"
    fastapi_logout = "/fastapi-logout"
    fastapi_secure = "/fastapi-secure"
    fastapi_session = "/fastapi-session"
    fastapi_verify_login = "/fastapi-verify-login"
