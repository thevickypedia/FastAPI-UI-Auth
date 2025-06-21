from fastapi.logger import logger
from fastapi.requests import Request
from fastapi.responses import HTMLResponse

from fastapiauthenticator import enums, models
from fastapiauthenticator.version import version


def session(request: Request) -> HTMLResponse:
    """Renders the session error page.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        HTMLResponse:
        Returns an HTML response templated using Jinja2.
    """
    return clear_session(
        request,
        models.templates.TemplateResponse(
            name="session.html",
            context={
                "request": request,
                "signin": enums.APIEndpoints.login,
                "reason": "Session expired or invalid.",
                "redirect": "/",  # todo: come from user input
                "version": f"v{version}",
            },
        ),
    )


def clear_session(request: Request, response: HTMLResponse) -> HTMLResponse:
    """Clear the session token from the response.

    Args:
        request: FastAPI ``request`` object.
        response: FastAPI ``response`` object.

    Returns:
        HTMLResponse:
        Returns the response object with the session token cleared.
    """
    for cookie in request.cookies:
        # Deletes all cookies stored in current session
        logger.info("Deleting cookie: '%s'", cookie)
        response.delete_cookie(cookie)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Authorization"] = ""
    return response


def login(request: Request) -> HTMLResponse:
    """Render the login page with the verification path and version.

    Returns:
        HTMLResponse:
        Rendered HTML response for the login page.
    """
    return models.templates.TemplateResponse(
        name="index.html",
        context={
            "request": request,
            "signin": enums.APIEndpoints.verify_login,
            "version": f"v{version}",
        },
    )


def error(request: Request) -> HTMLResponse:
    """Error endpoint for the monitoring page.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        HTMLResponse:
        Returns an HTML response templated using Jinja2.
    """
    return clear_session(
        request,
        models.templates.TemplateResponse(
            name="unauthorized.html",
            context={
                "request": request,
                "signin": enums.APIEndpoints.login,
                "redirect": "/",  # todo: come from user input
                "version": f"v{version}",
            },
        ),
    )
