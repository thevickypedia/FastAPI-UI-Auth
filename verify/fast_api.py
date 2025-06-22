import uvicorn
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRoute

import fastapiauthenticator


def root_page() -> RedirectResponse:
    """Re-direct the user to login page."""
    return RedirectResponse(url=fastapiauthenticator.APIEndpoints.fastapi_login)


def hello_world() -> JSONResponse:
    """A simple function that returns a JSON response with a greeting message."""
    return JSONResponse({"message": "Hello, World!"})


def secure_function(_: Request) -> HTMLResponse:
    """A sample secure function that can be used with the APIAuthenticatorException."""
    return HTMLResponse(
        content='<html><body style="background-color: gray;color: white"><h1>Authenticated</h1></body></html>',
        status_code=200,
    )


app = FastAPI(
    routes=[
        APIRoute(
            path="/",
            endpoint=root_page,
        ),
        APIRoute(
            path="/hello",
            endpoint=hello_world,
            methods=["GET"],
        ),
    ]
)
fastapiauthenticator.protect(
    app=app,
    secure_function=secure_function,
    route=APIRoute,
    secure_methods=["GET"],
    secure_path="/sensitive-data",
    session_timeout=300,
    fallback_button="NAVIGATE",
    fallback_path="/hello",
)

if __name__ == "__main__":
    uvicorn.run(app=app, port=8000)
