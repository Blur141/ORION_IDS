# ============================================================
# main.py — FastAPI Application: Routes + WebSocket
# ============================================================
# This is the HEART of the project.
# It defines all API endpoints and the WebSocket server.
#
# WHAT IS FastAPI?
#   FastAPI is a Python web framework. It lets you create
#   "routes" — URL paths that do something when visited.
#   Example: GET /packets → returns a list of packets as JSON
# ============================================================

import asyncio
import datetime
import json
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

import ids_project.storage as storage
import ids_project.sniffer as sniffer
from ids_project.state import sniffer_state

# -----------------------------------------------------------
# WebSocket Connection Manager
# -----------------------------------------------------------
# Keeps track of all currently connected WebSocket clients.
# When a packet arrives, we send it to ALL of them.

class ConnectionManager:
    def __init__(self):
        # List of active WebSocket connections
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection and register it."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Remove a connection when client disconnects."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """
        Send a message to ALL connected clients.
        If a client has disconnected, remove it silently.
        """
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead.append(connection)
        for d in dead:
            self.disconnect(d)


# Create the single global manager instance
manager = ConnectionManager()


# -----------------------------------------------------------
# Register the broadcast function with sniffer.py
# -----------------------------------------------------------
# sniffer.py needs a way to push data to WebSocket clients.
# We give it our manager.broadcast function as a callback.

async def broadcast_to_ws(message: dict):
    await manager.broadcast(message)

sniffer.set_broadcast_callback(broadcast_to_ws)


# -----------------------------------------------------------
# Connection Tracker (for /connections endpoint)
# -----------------------------------------------------------
# We log every HTTP request: IP, time, endpoint.
connection_log = []   # list of dicts


# -----------------------------------------------------------
# Lifespan (startup/shutdown logic)
# -----------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Code here runs on startup (before yield) and shutdown (after yield)."""
    print("🚀 IDS System Starting...")
    yield
    print("🛑 IDS System Shutting down...")
    sniffer_state["running"] = False


# -----------------------------------------------------------
# Create the FastAPI app
# -----------------------------------------------------------
app = FastAPI(
    title="Real-Time IDS System",
    description="Packet Classification & Intrusion Detection System",
    version="1.0.0",
    lifespan=lifespan
)

# Allow all origins for development (CORS = Cross-Origin Resource Sharing)
# This lets browsers on other ports/domains call our API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------
# Middleware: log every request (for /connections)
# -----------------------------------------------------------
@app.middleware("http")
async def log_connection(request: Request, call_next):
    """
    This runs on EVERY HTTP request, before reaching the route handler.
    We record the caller's IP, time, and which endpoint they hit.
    """
    client_ip = request.client.host if request.client else "unknown"
    endpoint  = request.url.path
    timestamp = datetime.datetime.now().isoformat()

    connection_log.append({
        "ip":        client_ip,
        "endpoint":  endpoint,
        "timestamp": timestamp
    })

    # Keep only last 1000 log entries
    if len(connection_log) > 1000:
        connection_log.pop(0)

    response = await call_next(request)
    return response


# ============================================================
# REST API ROUTES
# ============================================================

# -----------------------------------------------------------
# GET /  — Health check (just to confirm the server is alive)
# -----------------------------------------------------------
@app.get("/", summary="Health check")
async def root():
    return {
        "status": "running",
        "sniffer_active": sniffer_state["running"],
        "message": "IDS System is online 🛡️"
    }


# -----------------------------------------------------------
# POST /start  — Start packet capture
# -----------------------------------------------------------
@app.post("/start", summary="Start packet capture")
async def start_capture():
    """
    Starts the background packet sniffer.
    Clears previous data so you get a fresh session.
    """
    if sniffer_state["running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "Sniffer is already running."}
        )

    sniffer.start_sniffer()
    return {
        "status": "started",
        "message": "Packet capture has begun! 📡",
        "tip": "Visit /packets to see captured traffic."
    }


# -----------------------------------------------------------
# POST /stop  — Stop packet capture
# -----------------------------------------------------------
@app.post("/stop", summary="Stop packet capture")
async def stop_capture():
    """
    Stops the background packet sniffer.
    Data is preserved — you can still query /packets and /alerts.
    """
    if not sniffer_state["running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "Sniffer is not running."}
        )

    sniffer.stop_sniffer()
    return {
        "status": "stopped",
        "message": "Packet capture stopped. 🛑",
        "total_packets": len(storage.get_packets()),
        "total_alerts":  len(storage.get_alerts())
    }


# -----------------------------------------------------------
# GET /packets  — Get all captured packets
# -----------------------------------------------------------
@app.get("/packets", summary="Get all captured packets")
async def get_packets():
    """Returns the last 500 captured packets."""
    data = storage.get_packets()
    return {
        "count":   len(data),
        "packets": data
    }


# -----------------------------------------------------------
# GET /alerts  — Get all security alerts
# -----------------------------------------------------------
@app.get("/alerts", summary="Get security alerts")
async def get_alerts():
    """Returns all detected security alerts."""
    data = storage.get_alerts()
    return {
        "count":  len(data),
        "alerts": data
    }


# -----------------------------------------------------------
# GET /filter/{category}  — Filter packets by category
# -----------------------------------------------------------
@app.get("/filter/{category}", summary="Filter packets by category")
async def filter_packets(category: str):
    """
    Filter packets by traffic category.

    Valid categories: video, music, normal_browsing, other

    Example: GET /filter/video → returns only video traffic
    """
    valid = {"video", "music", "normal_browsing", "other"}
    if category not in valid:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"Invalid category '{category}'.",
                "valid_categories": list(valid)
            }
        )

    data = storage.get_packets(category=category)
    return {
        "category": category,
        "count":    len(data),
        "packets":  data
    }


# -----------------------------------------------------------
# GET /connections  — Get today's connection log
# -----------------------------------------------------------
@app.get("/connections", summary="Today's connection log")
async def get_connections():
    """
    Returns all API requests made today (IP + endpoint + time).
    This shows who is talking to the IDS API.
    """
    today = datetime.date.today().isoformat()  # e.g. "2024-01-15"

    # Filter to only today's entries
    todays = [
        entry for entry in connection_log
        if entry["timestamp"].startswith(today)
    ]

    return {
        "date":        today,
        "count":       len(todays),
        "connections": todays
    }


# -----------------------------------------------------------
# GET /status  — Quick status summary
# -----------------------------------------------------------
@app.get("/status", summary="System status")
async def get_status():
    return {
        "sniffer_running":   sniffer_state["running"],
        "packets_captured":  len(storage.get_packets()),
        "alerts_triggered":  len(storage.get_alerts()),
        "ws_clients_online": len(manager.active_connections)
    }


# ============================================================
# WEBSOCKET ENDPOINT
# ============================================================
# WebSocket is different from HTTP:
#   - HTTP: Client asks → Server answers → Connection closes
#   - WebSocket: Connection STAYS OPEN → Server can push anytime
#
# This means we can push live packets to the browser instantly!
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time packet + alert streaming.

    HOW TO TEST:
      Open browser DevTools Console and run:
        const ws = new WebSocket("ws://localhost:8000/ws");
        ws.onmessage = (e) => console.log(JSON.parse(e.data));

    Or use a tool like websocat:
        websocat ws://localhost:8000/ws
    """
    await manager.connect(websocket)
    try:
        # Send a welcome message immediately on connect
        await websocket.send_text(json.dumps({
            "type": "connected",
            "message": "🔌 Connected to IDS live stream!",
            "timestamp": datetime.datetime.now().isoformat()
        }))

        # Keep the connection alive by waiting for client messages.
        # If the client closes the tab, WebSocketDisconnect is raised.
        while True:
            # We wait for a message from the client (like a ping)
            # If nothing comes, we just wait. Packets are pushed
            # from process_packet() → broadcast_to_ws() → manager.broadcast()
            data = await websocket.receive_text()

            # Client can send {"action": "ping"} to check connection
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.datetime.now().isoformat()
                    }))
            except Exception:
                pass

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        print(f"WebSocket client disconnected. "
              f"Remaining: {len(manager.active_connections)}")
