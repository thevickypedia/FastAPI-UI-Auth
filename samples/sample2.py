import pathlib

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.routing import APIWebSocketRoute

import uiauth

app = FastAPI()


async def index():
    """Render the main index page for a wave pattern."""
    with open(pathlib.Path(__file__).parent / "index.html", "r", encoding="utf-8") as f:
        html = f.read()
    return HTMLResponse(html)


async def get_siriwave_js():
    """Serve the Siriwave JavaScript file."""
    return FileResponse(
        pathlib.Path(__file__).parent / "siriwave.umd.min.js",
        media_type="application/javascript",
    )


# Manage websocket connections and send commands
class ConnectionManager:
    """Manages WebSocket connections and sends commands to connected clients."""

    def __init__(self):
        """Initialize the connection manager with an empty list of active connections."""
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection and add it to the active connections."""
        await websocket.accept()
        self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket connection and remove it from the active connections."""
        self.active_connections.remove(websocket)

    async def send_command(self, command: str):
        """Send a command to all active WebSocket connections."""
        for connection in self.active_connections:
            await connection.send_text(command)


manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket):
    """Websocket endpoint to handle connections and commands."""
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from client but can handle if needed
            # For demo, echo back or ignore
            data = await websocket.receive_text()
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@app.post("/wave/{command}")
async def send_wave_command(command: str):
    """Unprotected endpoint to send commands to the wave generator.

    Args:
        command: The command to send to the wave generator, either "start" or "stop".

    Examples:
        curl -X POST http://localhost:8000/wave/start
        curl -X POST http://localhost:8000/wave/stop
    """
    if command not in ("start", "stop"):
        return {"error": "Invalid command"}
    await manager.send_command(command)
    return {"status": f"Command '{command}' sent."}


uiauth.protect(
    app=app,
    params=[
        uiauth.Parameters(
            function=get_siriwave_js,
            path="/siriwave.js",
        ),
        uiauth.Parameters(
            function=index,
            path="/",
        ),
        uiauth.Parameters(
            function=websocket_endpoint,
            route=APIWebSocketRoute,
            path="/ws",
        ),
    ],
)

if __name__ == "__main__":
    # sudo lsof -n -i :8000 | grep LISTEN
    uvicorn.run(app=app, host="0.0.0.0", port=8000)
