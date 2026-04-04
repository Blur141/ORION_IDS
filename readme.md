<p align="center">
  <h1 align="center">🛡️ ORION IDS</h1>
  <p align="center"><strong>Real-Time Packet Classification & Intrusion Detection System</strong></p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" />
    <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi" />
    <img src="https://img.shields.io/badge/Scapy-2.5-orange?style=flat-square" />
    <img src="https://img.shields.io/badge/WebSocket-Live-brightgreen?style=flat-square" />
    <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker" />
    <img src="https://img.shields.io/badge/Windows-Admin%20Required-0078D6?style=flat-square&logo=windows" />
  </p>
</p>

---

## 📌 Table of Contents

- [Overview](#overview)
- [What Changed — Changelog](#what-changed--changelog)
- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Running the App](#running-the-app)
- [Capture Modes](#capture-modes)
- [API Endpoints](#api-endpoints)
- [Debug Endpoints](#debug-endpoints)
- [WebSocket Usage](#websocket-usage)
- [Docker Setup](#docker-setup)
- [Testing the Endpoints](#testing-the-endpoints)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

ORION IDS is a beginner-friendly, real-time **Intrusion Detection System** built with Python. It captures live network packets, classifies traffic into categories (video, music, normal browsing), and detects basic attacks like ARP spoofing and plain-text credential leaks — all served through a REST API and live WebSocket stream.

Built to learn: Python backends, network programming, real-time systems, and Docker.

---

## What Changed — Changelog

### 🆕 Added

#### `classifier.py` — Complete rewrite
- **DNS-based classification** replaces pure port-based detection
- Added `VIDEO_DOMAINS` list: YouTube, Twitch, Netflix, Disney+, TikTok, Vimeo, Prime Video
- Added `MUSIC_DOMAINS` list: Spotify, Apple Music, SoundCloud, Deezer, Tidal
- Added `ip_category_table` — a live runtime dictionary mapping IP addresses to categories
- Added `update_dns_table(domain, ips)` — called when a DNS response is captured
- Added `_match_domain(domain)` — internal helper for substring domain matching
- `classify_packet()` signature changed: now takes `src_ip, dst_ip, src_port, dst_port` (was just ports)
- Classification now checks DNS table first, falls back to ports only if no match

#### `sniffer.py` — Major rewrite
- Added **automatic capture mode detection**: tests live capture on startup, falls back to simulation if blocked
- Added `seed_dns_for_domain(domain)` — resolves a domain using Python's `socket` library and seeds the table
- Added `seed_common_services()` — seeds all major streaming service IPs at every `/start`
- Added `get_best_interface()` — detects the correct network interface using a dummy UDP socket trick
- Added `process_dns_packet(packet)` — extracts domain→IP mappings from live DNS response packets
- Added `_simulation_loop()` — generates realistic traffic using real IPs when Docker blocks live capture
- Added `_test_live_capture()` — sniffs for 2 seconds to check if real packets are visible
- Added `_live_capture_loop()` and `_save_and_broadcast()` helper
- Added `capture_mode` global: `"live"` | `"simulation"` | `"stopped"`
- Added `active_interface` global: exposed to `main.py` for `/status`
- `process_packet()` now calls `process_dns_packet()` for all UDP port-53 packets
- `process_packet()` now passes `src_ip` and `dst_ip` to `classify_packet()`

#### `main.py` — New endpoints added
- Added `import classifier` at top
- **`GET /debug/dns-table`** — shows the full live IP→category mapping table
- **`POST /debug/seed-dns?domain=...`** — manually resolves and seeds a single domain
- **`POST /debug/reseed`** — re-runs full streaming service DNS seed
- **`GET /status`** — expanded with `capture_mode`, `active_interface`, `dns_table_size`

---

### 🔧 Fixed

| File | Fix |
|------|-----|
| `detector.py` | Fixed `import ids_project.storage as storage` → `import storage` (caused `ModuleNotFoundError` on startup) |
| `classifier.py` | Port-only classification broke because all modern streaming uses HTTPS port 443 — now uses DNS-based IP lookup |
| `sniffer.py` | Docker was silently capturing only internal bridge traffic (172.17.0.x) — now detects and reports this |
| `sniffer.py` | DNS table was never populated in Docker because host DNS traffic is invisible to containers — fixed via socket-based seeding |

---

### ❌ Removed / Changed

| What | Was | Now |
|------|-----|-----|
| `classify_packet()` signature | `(src_port, dst_port)` | `(src_ip, dst_ip, src_port, dst_port)` |
| Port-only classification | Primary method | Fallback only (used when IP not in DNS table) |
| `VIDEO_PORTS` set | Primary detection for YouTube etc. | Legacy fallback for old protocols (RTMP, RTSP) |
| Capture always live | Assumed live always worked | Now tests and auto-switches to simulation if needed |

---

## Features

- 🔴 **Live Packet Capture** — Scapy sniffs real network traffic (local run with Admin/sudo)
- 🧠 **DNS-Based Traffic Classification** — classifies by IP address learned from DNS, not just port numbers
- 🎬 **Traffic Categories** — `video`, `music`, `normal_browsing`, `other`
- 🚨 **Attack Detection** — ARP spoofing + plain-text credential leak detection
- 🔁 **Auto Simulation Mode** — falls back to realistic simulated traffic when Docker blocks capture
- 🌐 **REST API** — full CRUD-style endpoint set
- ⚡ **WebSocket Stream** — real-time push of every packet and alert to connected clients
- 🗂️ **Connection Logger** — logs every API request (IP, endpoint, timestamp)
- 🐳 **Docker Ready** — containerized, though live capture requires local run
- 🔬 **Debug Endpoints** — inspect DNS table, manually seed domains, re-seed all services

---

## Project Structure

```
ids_project/
│
├── main.py          # FastAPI app — all routes, WebSocket, debug endpoints, connection logger
├── sniffer.py       # Packet capture — live mode + simulation fallback, DNS seeding, interface detection
├── classifier.py    # Traffic classifier — DNS table lookup + port fallback
├── detector.py      # Attack detector — ARP spoofing + credential leak detection
├── storage.py       # In-memory storage — deque-based packet + alert store
├── state.py         # Shared start/stop flag
│
├── requirements.txt # Python dependencies
├── Dockerfile       # Docker container definition
├── .gitignore       # Git exclusions (venv, __pycache__, etc.)
└── README.md        # This file
```

---

## How It Works

### Why Port-Based Classification Failed (and what we use instead)

The original classifier checked port numbers: port 1935 = video, port 4070 = music. This broke because **every modern streaming service uses HTTPS on port 443** — the same port as banking, email, and everything else.

**The fix: DNS-based classification**

```
1. Browser wants YouTube
2. Browser asks DNS: "What IP is googlevideo.com?"
3. DNS responds: "142.250.80.46"        ← we intercept this (unencrypted!)
4. We store: ip_category_table["142.250.80.46"] = "video"
5. Browser connects to 142.250.80.46 on port 443
6. We see the packet → look up the IP → return "video" ✅
```

We also pre-seed the table at startup by resolving domains using Python's `socket` library — so classification works immediately, even in Docker.

### Two-Layer Classification

```
Packet arrives
     │
     ▼
Is dst_ip OR src_ip in ip_category_table?
     │
     ├── YES → return that category  (video / music)
     │
     └── NO  → check port numbers
                  ├── 1935/554 → video   (legacy RTMP/RTSP)
                  ├── 4070    → music   (legacy Spotify)
                  ├── 443/80  → normal_browsing
                  └── other   → other
```

### Capture Modes

```
/start is called
     │
     ├── Seed DNS table (socket.getaddrinfo for all streaming domains)
     ├── Detect best network interface
     ├── Test-sniff for 2 seconds
     │
     ├── Got real packets? → LIVE MODE   (running locally as Admin)
     └── Got only Docker bridge IPs? → SIMULATION MODE (realistic fake traffic)
```

### Attack Detection

**ARP Spoofing:** Builds a `{ IP → MAC }` table. If an IP claims a different MAC address than previously recorded, it is flagged as potential spoofing.

**Credential Leaks:** Scans TCP packets going to port 80 (unencrypted HTTP) for keywords like `password=`, `Authorization:`, `login=`. HTTPS traffic is encrypted and not scanned.

---

## Prerequisites

### For Local Run (Recommended — Windows)

| Requirement | Download |
|---|---|
| Python 3.11+ | [python.org](https://www.python.org/downloads/) |
| Npcap (packet capture driver) | [npcap.com](https://npcap.com/#download) |
| Git | [git-scm.com](https://git-scm.com/download/win) |
| **Admin privileges** | Required — right-click PowerShell → Run as administrator |

> ⚠️ During Npcap install, check **"Install Npcap in WinPcap API-compatible Mode"**

### For Docker Run

| Requirement | Download |
|---|---|
| Docker Desktop | [docker.com](https://www.docker.com/products/docker-desktop/) |
| WSL 2 (Windows) | Docker Desktop will prompt you to install it |

> ⚠️ Docker mode uses simulation — live host traffic is not visible inside containers. Use local run for real capture.

---

## Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ids-project.git
cd ids-project
```

### Step 2 — Create a Virtual Environment

```bash
# Create
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Mac/Linux)
source venv/bin/activate
```

> You will see `(venv)` appear in your prompt when it is active.

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the App

> ⚠️ **Must run PowerShell as Administrator** for live packet capture. Right-click → "Run as administrator".

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Open the interactive API docs at:
```
http://localhost:8000/docs
```

---

## Capture Modes

After calling `POST /start`, check `GET /status` to see which mode is active.

### Live Mode ✅
```json
{ "capture_mode": "live" }
```
Running locally as Administrator. Scapy is capturing real packets from your network interface. Open YouTube and call `GET /filter/video` to see classified packets.

### Simulation Mode ⚡
```json
{ "capture_mode": "simulation" }
```
Triggered automatically when live capture is blocked (Docker, missing Admin, no Npcap). Uses real IP addresses of YouTube/Spotify resolved via DNS at startup to generate realistic traffic. All categories (`video`, `music`, `normal_browsing`) will appear correctly. To get live mode, stop Docker and run locally as Administrator.

---

## API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/start` | Start capture — seeds DNS table, detects interface, begins sniffing |
| `POST` | `/stop` | Stop capture — data is preserved |
| `GET` | `/packets` | Last 500 captured packets |
| `GET` | `/alerts` | All security alerts |
| `GET` | `/filter/{category}` | Filter by: `video` / `music` / `normal_browsing` / `other` |
| `GET` | `/status` | Full system status including capture mode and DNS table size |
| `GET` | `/connections` | Today's API access log (IP, endpoint, timestamp) |
| `WS` | `/ws` | WebSocket — real-time packet and alert stream |

### Example `/status` Response

```json
{
  "sniffer_running": true,
  "capture_mode": "live",
  "packets_captured": 312,
  "alerts_triggered": 1,
  "ws_clients_online": 2,
  "active_interface": "Wi-Fi",
  "dns_table_size": 47,
  "tip": "If capture_mode is simulation, run locally as Admin (not Docker) for live packets."
}
```

---

## Debug Endpoints

These endpoints help you diagnose classification issues.

### `GET /debug/dns-table`

Shows the full IP→category mapping table built from DNS.

```json
{
  "total_entries": 47,
  "video_ip_count": 32,
  "music_ip_count": 15,
  "full_table": {
    "142.250.80.46": "video",
    "35.186.224.25": "music"
  }
}
```

**If `total_entries` is 0** → DNS seeding failed. Call `POST /debug/reseed`.

### `POST /debug/seed-dns?domain=googlevideo.com`

Manually resolves one domain and adds its IPs to the table.

```json
{
  "domain": "googlevideo.com",
  "resolved_ips": ["142.250.80.46", "142.250.80.47"],
  "category": "video",
  "message": "✅ 2 IPs added to classification table."
}
```

### `POST /debug/reseed`

Re-runs the full DNS seed for all streaming services.

```json
{
  "status": "reseeded",
  "ips_before": 0,
  "ips_after": 47,
  "new_ips_added": 47,
  "message": "✅ DNS table refreshed. 47 total IPs mapped."
}
```

---

## WebSocket Usage

Connect to `ws://localhost:8000/ws` for a real-time stream of every packet and alert.

### Connect from Browser Console

Open DevTools (`F12`) → Console tab:

```javascript
const ws = new WebSocket("ws://localhost:8000/ws");

ws.onopen = () => console.log("✅ Connected to ORION IDS!");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === "packet") {
    const p = data.data;
    console.log(`[${p.category}] ${p.src_ip}:${p.src_port} → ${p.dst_ip}:${p.dst_port} (${p.size}B) [${p.mode}]`);
  }
};

ws.onclose = () => console.log("🔌 Disconnected");
```

### Message Types

| `type` | When sent |
|--------|-----------|
| `connected` | Immediately after your WebSocket connects |
| `packet` | Every time a new packet is captured or simulated |
| `pong` | In response to `{"action": "ping"}` |

### Packet Fields

| Field | Example | Description |
|-------|---------|-------------|
| `src_ip` | `192.168.1.5` | Source IP address |
| `dst_ip` | `142.250.80.46` | Destination IP address |
| `src_port` | `54231` | Source port |
| `dst_port` | `443` | Destination port |
| `protocol` | `TCP` | Protocol: TCP, UDP, or OTHER |
| `category` | `video` | Classified category |
| `size` | `1200` | Packet size in bytes |
| `mode` | `live` | `live` or `simulation` |
| `timestamp` | `2026-04-04T...` | ISO timestamp |

---

## Docker Setup

> ⚠️ Docker mode runs in **simulation** — live capture of host traffic is architecturally impossible from inside a container. Use Docker to explore the API and WebSocket; use local run for real packet capture.

### Build and Run

```bash
# Build the image
docker build -t orion-ids .

# Run the container
docker run --privileged -p 8000:8000 --rm --name orion orion-ids
```

### Useful Docker Commands

```bash
docker ps                       # list running containers
docker logs -f orion            # follow live logs
docker exec -it orion bash      # shell inside container
docker stop orion               # stop container
docker rmi orion-ids            # delete image
```

---

## Testing the Endpoints

### Recommended — Interactive Docs

Visit `http://localhost:8000/docs` — FastAPI auto-generates a full test UI.

### Using curl

```bash
# Start capture
curl -X POST http://localhost:8000/start

# Check status and capture mode
curl http://localhost:8000/status

# See what IPs are in the DNS table
curl http://localhost:8000/debug/dns-table

# Get all packets
curl http://localhost:8000/packets

# Filter for video only
curl http://localhost:8000/filter/video

# Check for security alerts
curl http://localhost:8000/alerts

# Manually seed YouTube if missing
curl -X POST "http://localhost:8000/debug/seed-dns?domain=googlevideo.com"

# Re-seed everything
curl -X POST http://localhost:8000/debug/reseed

# Stop capture
curl -X POST http://localhost:8000/stop
```

---

## Known Limitations

| Limitation | Reason | Workaround |
|---|---|---|
| Docker shows only simulation | Kernel-level network isolation | Run locally as Administrator |
| DNS table IPs can rotate | CDNs change IPs frequently | Call `POST /debug/reseed` to refresh |
| HTTPS content not inspected | Encrypted — by design | Classification by IP, not content |
| Windows requires Admin | Npcap/WinPcap needs raw socket access | Always run PowerShell as Administrator |
| DNS pre-seed covers known services only | We can only seed what we know | Live DNS capture adds new services at runtime |

---

## Contributing

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add: description"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

### Ideas for Contributions

- Add more streaming service domains to `VIDEO_DOMAINS` / `MUSIC_DOMAINS`
- Add a simple web dashboard frontend
- Add SQLite for persistent packet storage
- Add email/desktop alert notifications
- Add port scan detection
- Add SYN flood detection

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

<div align="center">
  <strong>ORION IDS</strong> — Built with FastAPI + Scapy + WebSockets<br>
  <sub>A beginner Python project for learning backend development and network programming</sub>
</div>