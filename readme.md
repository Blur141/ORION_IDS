<div align="center">

<h1>🛡️ Operational Reconnaissance & Intelligent
Observation Network - ORION</h1>

<p><strong>Real-Time Packet Classification & Intrusion Detection System</strong></p>

<p>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.111-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Scapy-2.5-FF6B35?style=for-the-badge" />
  <img src="https://img.shields.io/badge/WebSocket-Live-22C55E?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows-Admin%20Required-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
</p>

<p>
  A beginner-friendly backend project that captures live network packets,<br>
  classifies your internet traffic in real time, and detects basic network attacks —<br>
  all served through a clean REST API and a live WebSocket stream.
</p>

</div>

---

## 📌 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Tech Stack](#-tech-stack)
4. [Project Structure](#-project-structure)
5. [How It Works](#-how-it-works)
6. [Prerequisites](#-prerequisites)
7. [Installation & Setup](#-installation--setup)
8. [Running the App](#-running-the-app)
9. [Capture Modes](#-capture-modes)
10. [API Endpoints](#-api-endpoints)
11. [WebSocket Usage](#-websocket-usage)
12. [Testing the Endpoints](#-testing-the-endpoints)
13. [Known Limitations](#-known-limitations)
14. [Future Plans](#-future-plans)
15. [Contributing](#-contributing)
17. [License](#-license)

---

## 🔭 Overview

ORION IDS is a **real-time network monitoring tool** built entirely in Python. It sits quietly in the background, watches your network traffic, and tells you what is happening — whether you are streaming YouTube, listening to Spotify, or just browsing the web. At the same time, it watches for signs of network attacks and raises alerts if something suspicious is detected.

This project is designed to be **beginner-friendly**. Every file is heavily commented, the architecture is kept simple, and this README walks you through everything from installation to testing.

> **What you will learn by building this project:**
> Python FastAPI, Scapy packet capture, WebSockets, threading, DNS resolution, REST API design, Docker containerisation, and Git version control.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔴 **Live Packet Capture** | Scapy sniffs real network packets from your machine |
| 🧠 **DNS-Based Classification** | Identifies traffic by IP address learned from DNS — not just ports |
| 🎬 **Traffic Categories** | Labels every packet as `video`, `music`, `normal_browsing`, or `other` |
| 🚨 **ARP Spoofing Detection** | Detects IP/MAC address conflicts that indicate a man-in-the-middle attack |
| 🔑 **Credential Leak Detection** | Scans plain HTTP traffic for passwords sent in the clear |
| ⚡ **Auto Simulation Mode** | Falls back to realistic simulated traffic when Docker blocks capture |
| 🌐 **REST API** | Full set of HTTP endpoints to control and query the system |
| 📡 **WebSocket Stream** | Real-time push of every packet and alert to connected clients |
| 🗂️ **Connection Logger** | Logs every API request with IP address, endpoint, and timestamp |
| 🔬 **Debug Endpoints** | Inspect the DNS table, manually seed domains, re-seed all services |

---

## 🛠️ Tech Stack

| Technology | Version | Purpose |
|---|---|---|
| [Python](https://www.python.org/) | 3.11+ | Core programming language |
| [FastAPI](https://fastapi.tiangolo.com/) | 0.111 | Web framework for building REST APIs |
| [Uvicorn](https://www.uvicorn.org/) | 0.30 | ASGI server that runs FastAPI |
| [Scapy](https://scapy.net/) | 2.5 | Network packet capture and analysis |
| [WebSockets](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API) | Built-in | Real-time bidirectional communication |
| [Docker](https://www.docker.com/) | Latest | Containerisation and deployment |
| [Npcap](https://npcap.com/) | Latest | Windows packet capture driver (required) |

---

## 📁 Project Structure

```
ids_project/
│
├── main.py          →  FastAPI app: all HTTP routes, WebSocket, debug endpoints, connection logger
├── sniffer.py       →  Packet capture engine: live mode, simulation fallback, DNS seeding
├── classifier.py    →  Traffic classifier: DNS table lookup + port-based fallback
├── detector.py      →  Attack detector: ARP spoofing + credential leak scanning
├── storage.py       →  In-memory storage: rolling deque for packets and alerts
├── state.py         →  Shared on/off flag: controls sniffer start/stop across modules
│
├── requirements.txt →  Python package dependencies
├── Dockerfile       →  Container build instructions
├── .gitignore       →  Files excluded from Git (venv, __pycache__, etc.)
└── README.md        →  This file
```

---

## ⚙️ How It Works

### Why Not Just Use Port Numbers?

The simplest approach to classifying traffic is checking port numbers — port 443 is HTTPS, port 53 is DNS, and so on. The problem is that **every modern streaming service uses HTTPS on port 443**, the exact same port as your bank, your email, and every other website. Port numbers alone cannot tell YouTube apart from Google Docs.

### DNS-Based Classification

When your browser wants to load YouTube, it first asks:

```
Browser  →  "What is the IP address of googlevideo.com?"
DNS      →  "It is 142.250.80.46"
```

That DNS conversation is **unencrypted** — we can read it. ORION IDS intercepts these DNS responses, records which IP addresses belong to which service, and builds a live lookup table. When a packet later arrives on port 443 going to `142.250.80.46`, we look up that IP and correctly return `video`.

```
Packet arrives
      │
      ▼
 Is dst_ip in the DNS table?
      │
      ├── YES  →  return category from table  (video / music)
      │
      └── NO   →  check port numbers
                    ├── 1935 / 554  →  video  (legacy RTMP/RTSP)
                    ├── 4070        →  music  (legacy Spotify)
                    ├── 443 / 80    →  normal_browsing
                    └── anything else  →  other
```

Additionally, on every `/start`, the app pre-seeds the DNS table by resolving major streaming domains using Python's `socket` library — so classification works from the very first packet, without waiting for DNS traffic.

### Attack Detection

**ARP Spoofing** — Builds a table of `IP → MAC address` mappings. If an IP suddenly claims a different MAC address than previously recorded, it raises an alert. This is a sign of a man-in-the-middle attack on your local network.

**Credential Leaks** — Scans TCP packets heading to port 80 (plain HTTP, not encrypted) for keywords like `password=`, `Authorization:`, and `login=`. HTTPS traffic is encrypted and cannot be read — only unprotected HTTP is scanned.

### Capture Modes

```
/start is called
      │
      ├── Seed DNS table (resolves YouTube, Spotify etc. → IPs)
      ├── Detect best network interface
      ├── Test-sniff for 2 seconds
      │
      ├── Got real packets?  →  LIVE MODE        (local Admin run)
      └── Got Docker IPs only?  →  SIMULATION MODE  (automatic fallback)
```

---

## 🖥️ Prerequisites

### For Local Run (Recommended — gives live capture)

| Requirement | Why it is needed | Download |
|---|---|---|
| **Python 3.11+** | Runs the application | [python.org](https://www.python.org/downloads/) |
| **Npcap** | Windows driver that lets Scapy capture packets | [npcap.com](https://npcap.com/#download) |
| **Git** | Version control | [git-scm.com](https://git-scm.com/download/win) |
| **Admin rights** | Scapy needs raw socket access to the network card | Right-click PowerShell → Run as administrator |

> ⚠️ During **Npcap** installation, check the box that says **"Install Npcap in WinPcap API-compatible Mode"**. Without this, Scapy cannot capture packets on Windows.

### For Docker Run (simulation mode only)

| Requirement | Download |
|---|---|
| **Docker Desktop** | [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/) |
| **WSL 2** (Windows) | Docker Desktop will prompt you to install it automatically |

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/Blur141/ORION_IDS.git
cd orion-ids
```

### Step 2 — Create a Virtual Environment

A virtual environment keeps your project's packages separate from the rest of your system. Think of it as a clean, private Python installation just for this project.

```bash
# Create the virtual environment
python -m venv venv

# Activate it — Windows
venv\Scripts\activate

# Activate it — Mac / Linux
source venv/bin/activate
```

You will know it is active when you see `(venv)` at the start of your terminal prompt.

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs FastAPI, Uvicorn, and Scapy. It may take a minute.

---

## ▶️ Running the App

> ⚠️ **Windows — you must open PowerShell as Administrator** before running. Right-click the PowerShell icon and choose "Run as administrator". Without this, Scapy cannot access the network card.

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

| Flag | What it does |
|---|---|
| `--reload` | Automatically restarts the server when you edit and save a file |
| `--host 0.0.0.0` | Accepts connections from any device on your network |
| `--port 8000` | Listens on port 8000 |

Once the server starts, open your browser and go to:

```
http://localhost:8000/docs
```

This is FastAPI's **built-in interactive documentation**. Every endpoint is listed here and you can test them all directly from the browser — no extra tools needed.

---

## 📡 Capture Modes

After calling `POST /start`, check `GET /status` to see which mode is running.

### ✅ Live Mode
```json
{ "capture_mode": "live" }
```
You are running locally as Administrator with Npcap installed. Scapy is capturing real packets from your network card. Open YouTube and call `GET /filter/video` — you will see real packets labelled as `video`.

### ⚡ Simulation Mode
```json
{ "capture_mode": "simulation" }
```
Live capture was blocked — either you are running inside Docker, or the app does not have Administrator privileges. The system automatically switches to simulation mode. It uses the **real IP addresses** of YouTube, Spotify, and other services (resolved via DNS at startup) to generate realistic traffic. All categories appear correctly — `video`, `music`, `normal_browsing` — so you can explore the full API without live capture.

**To switch from simulation to live:** Close Docker, open PowerShell as Administrator, and run the app locally.

---

## 🌐 API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check — confirms the server is running |
| `POST` | `/start` | Start capture: seeds DNS, detects interface, begins sniffing |
| `POST` | `/stop` | Stop capture — all data is preserved for querying |
| `GET` | `/packets` | Returns the last 500 captured packets |
| `GET` | `/alerts` | Returns all security alerts |
| `GET` | `/filter/{category}` | Filter packets by category |
| `GET` | `/status` | Full system status |
| `GET` | `/connections` | Today's API access log |
| `WS` | `/ws` | WebSocket — real-time live stream |

### Filter Categories

```
/filter/video
/filter/music
/filter/normal_browsing
/filter/other
```

### Debug Endpoints

These help you diagnose why packets might not be classifying correctly.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/debug/dns-table` | Shows every IP address currently mapped to a category |
| `POST` | `/debug/seed-dns?domain=youtube.com` | Manually resolves and seeds one domain |
| `POST` | `/debug/reseed` | Re-seeds all streaming services at once |

### Example `/status` Response

```json
{
  "sniffer_running": true,
  "capture_mode": "live",
  "packets_captured": 312,
  "alerts_triggered": 1,
  "ws_clients_online": 2,
  "active_interface": "Wi-Fi",
  "dns_table_size": 47
}
```

---

## 🔌 WebSocket Usage

Connect to `ws://localhost:8000/ws` to receive a live stream of every packet and alert the moment it is captured.

### Connect from Your Browser Console

Open any website, press `F12` to open DevTools, go to the **Console** tab, and paste this:

```javascript
const ws = new WebSocket("ws://localhost:8000/ws");

ws.onopen = () => console.log("✅ Connected to ORION IDS!");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.type === "packet") {
    const p = data.data;
    console.log(
      `[${p.category.toUpperCase()}]  ${p.src_ip} → ${p.dst_ip}  ` +
      `port ${p.dst_port}  ${p.size}B  (${p.mode})`
    );
  }
};

ws.onclose = () => console.log("🔌 Disconnected");
```

### Message Types

| `type` | When it is sent |
|--------|----------------|
| `connected` | Immediately after connecting |
| `packet` | Every time a packet is captured or simulated |
| `pong` | In response to `{"action": "ping"}` |

### Packet Object Fields

| Field | Example | Description |
|-------|---------|-------------|
| `src_ip` | `192.168.1.5` | Source IP address |
| `dst_ip` | `142.250.80.46` | Destination IP address |
| `src_port` | `54231` | Source port number |
| `dst_port` | `443` | Destination port number |
| `protocol` | `TCP` | Protocol: TCP, UDP, or OTHER |
| `category` | `video` | Classified traffic category |
| `size` | `1200` | Packet size in bytes |
| `mode` | `live` | Whether this is a live or simulated packet |
| `timestamp` | `2026-04-04T12:00:00` | Exact time the packet was captured |

---

## 🧪 Testing the Endpoints

### Option 1 — Interactive Docs (Easiest)

Go to `http://localhost:8000/docs` — every endpoint is listed with a form to fill in and an Execute button.

### Option 2 — curl Commands

```bash
# 1. Start capturing
curl -X POST http://localhost:8000/start

# 2. Check what mode is running (live or simulation)
curl http://localhost:8000/status

# 3. Check the DNS table — should have 40+ entries
curl http://localhost:8000/debug/dns-table

# 4. Get all packets
curl http://localhost:8000/packets

# 5. Get only video traffic
curl http://localhost:8000/filter/video

# 6. Get only music traffic
curl http://localhost:8000/filter/music

# 7. Check for security alerts
curl http://localhost:8000/alerts

# 8. Re-seed the DNS table if classification is not working
curl -X POST http://localhost:8000/debug/reseed

# 9. Manually seed a specific domain
curl -X POST "http://localhost:8000/debug/seed-dns?domain=googlevideo.com"

# 10. Stop capturing
curl -X POST http://localhost:8000/stop
```

---

## ⚠️ Known Limitations

| Limitation | Reason | Workaround |
|---|---|---|
| Docker shows simulation only | Containers cannot access host network traffic — kernel isolation | Run locally as Administrator |
| CDN IP addresses can change | Streaming services rotate their server IPs regularly | Call `POST /debug/reseed` to refresh |
| HTTPS content is not inspected | Traffic is encrypted — this is correct behaviour | Classification works by IP address, not content |
| Windows requires Npcap + Admin | Raw socket access needs elevated privileges | Always run PowerShell as Administrator |
| DNS pre-seed covers known services only | Only services listed in `classifier.py` are pre-seeded | Add domains to `VIDEO_DOMAINS` or `MUSIC_DOMAINS` in `classifier.py` |

---

## 🔮 Future Plans

These features are planned for upcoming versions:

- [ ] **React Frontend Dashboard** — live packet feed, charts by category, alert panel, dark theme
- [ ] **SQLite Storage** — persist packets and alerts across restarts instead of in-memory only
- [ ] **Port Scan Detection** — detect when a device is scanning your open ports
- [ ] **SYN Flood Detection** — detect basic denial-of-service patterns
- [ ] **Email Alerts** — send an email when a high-severity alert is triggered
- [ ] **Packet Export** — download captured packets as CSV or JSON
- [ ] **Custom Domain Rules** — let users add their own domain → category mappings via the API
- [ ] **User Authentication** — protect the API with API keys or login

---

## 🤝 Contributing

Contributions are welcome. Here is how to get started:

```bash
# 1. Fork this repository on GitHub

# 2. Clone your fork
git clone https://github.com/Blur141/ORION_IDS.git
cd orion-ids

# 3. Create a branch for your feature
git checkout -b feature/your-feature-name

# 4. Make your changes, then stage and commit
git add .
git commit -m "Add: description of what you changed"

# 5. Push to your fork
git push origin feature/your-feature-name

# 6. Open a Pull Request on GitHub
```

### Good first contributions

- Add more domains to `VIDEO_DOMAINS` or `MUSIC_DOMAINS` in `classifier.py`
- Improve the Dockerfile
- Write tests for the classifier logic
- Fix a bug or improve error messages

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

You are free to use, modify, and distribute this code for any purpose.

---

<div align="center">

<br>

**🛡️ ORION IDS**

Built with Python · FastAPI · Scapy · WebSockets

<sub>A beginner project for learning Python backend development and network programming</sub>

<br>

</div>