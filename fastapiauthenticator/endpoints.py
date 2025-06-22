from fastapi.requests import Request
from fastapi.responses import HTMLResponse

from fastapiauthenticator import enums, models, utils
from fastapiauthenticator.version import version


def session(request: Request) -> HTMLResponse:
    """Renders the session error page.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        HTMLResponse:
        Returns an HTML response templated using Jinja2.
    """
    return utils.clear_session(
        request,
        models.templates.TemplateResponse(
            name="session.html",
            context={
                "request": request,
                "signin": enums.APIEndpoints.fastapi_login,
                "reason": "Session expired or invalid.",
                "fallback_path": models.fallback.path,
                "fallback_button": models.fallback.button,
                "version": f"v{version}",
            },
        ),
    )


def login(request: Request) -> HTMLResponse:
    """Render the login page with the verification path and version.

    Returns:
        HTMLResponse:
        Rendered HTML response for the login page.
    """
    return utils.clear_session(
        request,
        models.templates.TemplateResponse(
            name="index.html",
            context={
                "request": request,
                "signin": enums.APIEndpoints.fastapi_verify_login,
                "version": f"v{version}",
            },
        ),
    )


def error(request: Request) -> HTMLResponse:
    """Error endpoint for the authenticator.

    Args:
        request: Reference to the FastAPI request object.

    Returns:
        HTMLResponse:
        Returns an HTML response templated using Jinja2.
    """
    return utils.clear_session(
        request,
        models.templates.TemplateResponse(
            name="unauthorized.html",
            context={
                "request": request,
                "signin": enums.APIEndpoints.fastapi_login,
                "fallback_path": models.fallback.path,
                "fallback_button": models.fallback.button,
                "version": f"v{version}",
            },
        ),
    )
