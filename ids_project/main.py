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

import storage
import sniffer
import classifier
from state import sniffer_state

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
        "capture_mode":      sniffer.capture_mode,
        "packets_captured":  len(storage.get_packets()),
        "alerts_triggered":  len(storage.get_alerts()),
        "ws_clients_online": len(manager.active_connections),
        "active_interface":  sniffer.active_interface or "auto (default)",
        "dns_table_size":    len(classifier.ip_category_table),
        "tip": "If capture_mode is simulation, run locally as Admin (not Docker) for live packets."
    }


# -----------------------------------------------------------
# GET /debug/dns-table  — See what IPs have been classified
# -----------------------------------------------------------
@app.get("/debug/dns-table", summary="View the live DNS→IP classification table")
async def get_dns_table():
    """
    Shows the current IP→category mapping table.

    USE THIS TO DIAGNOSE why packets are being classified
    as 'other' instead of 'video' or 'music'.

    If you open YouTube and your packets show [other]:
      1. Call this endpoint
      2. Check if any IPs map to "video"
      3. If the table is empty → DNS seeding failed
      4. Use POST /debug/seed-dns?domain=googlevideo.com to fix

    Returns a dict like:
      { "142.250.80.46": "video", "35.186.224.25": "music", ... }
    """
    table = classifier.ip_category_table
    video_ips = [ip for ip, cat in table.items() if cat == "video"]
    music_ips = [ip for ip, cat in table.items() if cat == "music"]

    return {
        "total_entries":  len(table),
        "video_ip_count": len(video_ips),
        "music_ip_count": len(music_ips),
        "full_table":     table,
        "tip": "If total_entries is 0, call POST /debug/seed-dns?domain=youtube.com"
    }


# -----------------------------------------------------------
# POST /debug/seed-dns  — Manually seed a domain's IPs
# -----------------------------------------------------------
@app.post("/debug/seed-dns", summary="Manually resolve and seed a domain into the DNS table")
async def seed_dns(domain: str):
    """
    Manually resolves a domain and adds its IPs to the
    classification table.

    THIS IS THE FIX FOR DOCKER:
    When running in Docker, the container can't see your
    browser's DNS queries. Call this endpoint to manually
    seed the important domains.

    Examples to call:
      POST /debug/seed-dns?domain=youtube.com
      POST /debug/seed-dns?domain=googlevideo.com
      POST /debug/seed-dns?domain=spotify.com
      POST /debug/seed-dns?domain=scdn.co

    After calling these, packets to those IPs will be
    classified as "video" or "music" correctly.
    """
    ips = sniffer.seed_dns_for_domain(domain)

    if not ips:
        return JSONResponse(
            status_code=400,
            content={
                "error": f"Could not resolve '{domain}'.",
                "tip": "Check the domain spelling. Some CDN domains may not resolve directly."
            }
        )

    return {
        "domain":       domain,
        "resolved_ips": ips,
        "category":     classifier.ip_category_table.get(ips[0], "unknown"),
        "message":      f"✅ {len(ips)} IPs added to classification table."
    }


# -----------------------------------------------------------
# POST /debug/reseed  — Re-run the full streaming service seed
# -----------------------------------------------------------
@app.post("/debug/reseed", summary="Re-seed all streaming service IPs")
async def reseed_all():
    """
    Re-runs the full DNS seeding for all known streaming services.
    Useful if classification stops working or the table gets stale.

    Resolves: YouTube, Twitch, Netflix, Spotify, SoundCloud,
    Disney+, Vimeo, TikTok, Deezer, Apple Music, and more.
    """
    old_count = len(classifier.ip_category_table)
    sniffer.seed_common_services()
    new_count = len(classifier.ip_category_table)

    return {
        "status":          "reseeded",
        "ips_before":      old_count,
        "ips_after":       new_count,
        "new_ips_added":   new_count - old_count,
        "active_interface": sniffer.active_interface or "auto",
        "message":         f"✅ DNS table refreshed. {new_count} total IPs mapped."
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