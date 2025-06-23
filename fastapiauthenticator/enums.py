from enum import StrEnum


class APIMethods(StrEnum):
    """HTTP methods for API requests.

    >>> APIMethods

    """

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"


class APIEndpoints(StrEnum):
    """API endpoints for all the routes.

    >>> APIEndpoints

    """

    fastapi_error = "/fastapi-error"
    fastapi_login = "/fastapi-login"
    fastapi_logout = "/fastapi-logout"
    fastapi_session = "/fastapi-session"
    fastapi_verify_login = "/fastapi-verify-login"
