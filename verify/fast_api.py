import uvicorn
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.routing import APIRoute

import pyapiauthenticator

app = FastAPI()


def root_page() -> RedirectResponse:
    """Re-direct the user to login page."""
    return RedirectResponse(url="/login")


def secure_function(_: Request) -> HTMLResponse:
    """A sample secure function that can be used with the APIAuthenticatorException."""
    return HTMLResponse(
        content='<html><body style="background-color: gray;color: white"><h1>Authenticated</h1></body></html>',
        status_code=200,
    )


api_authenticator = pyapiauthenticator.FastAPIAuthenticator(
    app=app, secure_function=secure_function
)
app.routes.append(
    APIRoute(
        path="/",
        endpoint=root_page,
    )
)
api_authenticator.secure()

if __name__ == "__main__":
    uvicorn.run(app=app, port=8000)
