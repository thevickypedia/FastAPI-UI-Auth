import pathlib

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.routing import APIRoute, APIWebSocketRoute

import fastapiauthenticator

app = FastAPI()


@app.get("/")
async def root_page() -> RedirectResponse:
    """Re-direct the user to login page."""
    return RedirectResponse(url=fastapiauthenticator.APIEndpoints.fastapi_login)


async def get():
    with open(pathlib.Path(__file__).parent / "index.html", "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(html)


@app.get("/siriwave.js")
async def get_siriwave_js():
    print("Responding to file request")
    return FileResponse(pathlib.Path(__file__).parent / "siriwave.umd.min.js", media_type="application/javascript")


# Manage websocket connections and send commands
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_command(self, command: str):
        for connection in self.active_connections:
            await connection.send_text(command)


manager = ConnectionManager()


# @app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()  # We don't expect messages from client but can handle if needed
            # For demo, echo back or ignore
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@app.post("/wave/{command}")
async def send_wave_command(command: str):
    if command not in ("start", "stop"):
        return {"error": "Invalid command"}
    await manager.send_command(command)
    return {"status": f"Command '{command}' sent."}


fastapiauthenticator.protect(
    app=app,
    secure_function=get,
    route=APIRoute,
)
fastapiauthenticator.protect(
    app=app,
    secure_function=websocket_endpoint,
    secure_path="/ws",
    route=APIWebSocketRoute,
)

if __name__ == "__main__":
    # sudo lsof -n -i :8000 | grep LISTEN
    uvicorn.run(app=app, host="0.0.0.0", port=8000)
