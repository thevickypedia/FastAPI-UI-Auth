from enum import StrEnum


class APIEndpoints(StrEnum):
    """API endpoints for all the routes.

    >>> APIEndpoints

    """

    login = "/login"
    logout = "/logout"
    error = "/error"
    verify_login = "/verify-login"
