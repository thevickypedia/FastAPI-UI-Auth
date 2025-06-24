import uvicorn
from fastapi import FastAPI, status
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute

import fastapiauthenticator as auth


def hello_world() -> JSONResponse:
    """A simple function that returns a JSON response with a greeting message."""
    return JSONResponse({"message": "Hello, World!"})


def secure_function(_: Request) -> HTMLResponse:
    """A sample secure function that can be used with the APIAuthenticatorException."""
    return HTMLResponse(
        content='<html><body style="background-color: gray;color: white"><h1>Authenticated</h1></body></html>',
        status_code=status.HTTP_200_OK,
    )


app = FastAPI(
    routes=[
        APIRoute(
            path="/hello",
            endpoint=hello_world,
            methods=["GET"],
        ),
    ]
)
auth.protect(
    app=app,
    params=auth.Parameters(
        path="/sensitive-data",
        function=secure_function,
    ),
    fallback_button="NAVIGATE",
    fallback_path="/hello",
    timeout=3,
)

if __name__ == "__main__":
    uvicorn.run(app=app, port=8000)
