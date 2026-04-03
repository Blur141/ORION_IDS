# 🛡️ Operational Reconnaissance & Intelligent Observation Network - ORION

A beginner-friendly backend project built with **FastAPI** and **Scapy** that captures live network packets, classifies traffic in real time, and detects basic network attacks — all accessible via REST APIs and a live WebSocket stream.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation & Setup](#installation--setup)
- [Running the App](#running-the-app)
- [API Endpoints](#api-endpoints)
- [WebSocket Usage](#websocket-usage)
- [Docker Setup](#docker-setup)
- [How It Works](#how-it-works)
- [Testing the Endpoints](#testing-the-endpoints)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This project is a real-time **Intrusion Detection System (IDS)** that runs on your local machine. It sniffs your network traffic, classifies it into categories (video, music, normal browsing), and alerts you when it detects suspicious patterns like ARP spoofing or plain-text credential leaks.

It is designed as a **learning project** for beginners who want to understand:
- How Python backend APIs work
- How network packets are captured and analyzed
- How WebSockets enable real-time communication
- How to containerize an app with Docker

---

## Features

- **Live Packet Capture** — sniffs real network traffic using Scapy
- **Traffic Classification** — labels packets as `video`, `music`, `normal_browsing`, or `other` based on port numbers
- **Attack Detection**
  - ARP Spoofing — detects IP/MAC address conflicts on your LAN
  - Credential Leaks — scans plain HTTP (port 80) payloads for password keywords
- **REST API** — start/stop capture, query packets, filter by category, view alerts
- **WebSocket Stream** — real-time push of packets and alerts to connected clients
- **Connection Logger** — logs every API request (IP, endpoint, timestamp)
- **Docker Ready** — fully containerized with a single `docker run` command

---

## Project Structure

```
ids_project/
│
├── main.py          # FastAPI app — all routes, WebSocket, connection logger
├── sniffer.py       # Packet capture engine (Scapy) — runs in background thread
├── classifier.py    # Traffic classifier — port-based category detection
├── detector.py      # Attack detector — ARP spoofing + credential leak checks
├── storage.py       # In-memory storage for packets and alerts (deque-based)
├── state.py         # Shared start/stop flag used across all modules
│
├── requirements.txt # Python dependencies
├── Dockerfile       # Docker container definition
├── .gitignore       # Files excluded from Git
└── README.md        # This file
```

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| [FastAPI](https://fastapi.tiangolo.com/) | Web framework for building REST APIs |
| [Uvicorn](https://www.uvicorn.org/) | ASGI server that runs FastAPI |
| [Scapy](https://scapy.net/) | Packet capture and analysis library |
| [Python 3.11+](https://www.python.org/) | Programming language |
| [Docker](https://www.docker.com/) | Containerization |
| WebSockets | Real-time bidirectional communication |

---

## Prerequisites

Before you begin, make sure you have the following installed:

### For Local Run (Windows)

- **Python 3.11+** → [python.org](https://www.python.org/downloads/)
- **Npcap** (packet capture driver) → [npcap.com](https://npcap.com/#download)
  - During install, check **"Install Npcap in WinPcap API-compatible Mode"**
- **Git** → [git-scm.com](https://git-scm.com/download/win)
- **Admin privileges** — Scapy requires Administrator access to capture packets

### For Docker Run

- **Docker Desktop** → [docker.com](https://www.docker.com/products/docker-desktop/)
  - Requires WSL 2 on Windows (Docker Desktop will prompt you to install it)

---

## Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ids-project.git
cd ids-project
```

### Step 2 — Create a Virtual Environment

```bash
# Create the virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate

# Activate it (Mac/Linux)
source venv/bin/activate
```

> You'll know it's active when you see `(venv)` at the start of your terminal prompt.

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the App

> ⚠️ **Windows users:** Open PowerShell or Command Prompt **as Administrator** before running. Scapy needs admin rights to access network interfaces.

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

| Flag | Meaning |
|------|---------|
| `--reload` | Auto-restart on code changes (great for development) |
| `--host 0.0.0.0` | Accept connections from any network interface |
| `--port 8000` | Listen on port 8000 |

Once running, open your browser and visit:

```
http://localhost:8000/docs
```

This opens FastAPI's **interactive documentation** — you can test every endpoint directly from the browser without any extra tools.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check — confirms server is running |
| `POST` | `/start` | Start packet capture (clears previous data) |
| `POST` | `/stop` | Stop packet capture (data is preserved) |
| `GET` | `/packets` | Get the last 500 captured packets |
| `GET` | `/alerts` | Get all detected security alerts |
| `GET` | `/filter/{category}` | Filter packets by category |
| `GET` | `/status` | Live stats: running state, counts, WS clients |
| `GET` | `/connections` | Today's API access log (IP, endpoint, time) |
| `WS` | `/ws` | WebSocket — real-time packet and alert stream |

### Valid Filter Categories

```
/filter/video
/filter/music
/filter/normal_browsing
/filter/other
```

### Example Responses

**GET /status**
```json
{
  "sniffer_running": true,
  "packets_captured": 142,
  "alerts_triggered": 2,
  "ws_clients_online": 1
}
```

**GET /alerts**
```json
{
  "count": 1,
  "alerts": [
    {
      "type": "ARP Spoofing",
      "detail": "IP 192.168.1.1 previously had MAC aa:bb:cc:dd:ee:ff but now claims MAC 11:22:33:44:55:66",
      "severity": "HIGH",
      "timestamp": "2024-01-15T14:32:01.123456"
    }
  ]
}
```

---

## WebSocket Usage

Connect to the WebSocket at `ws://localhost:8000/ws` to receive a live stream of packets and alerts.

### Connect from Browser Console

Open your browser, press `F12` to open DevTools, go to the **Console** tab, and paste:

```javascript
const ws = new WebSocket("ws://localhost:8000/ws");

ws.onopen = () => console.log("✅ Connected to IDS live stream!");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === "packet") {
    console.log(`📦 ${data.data.src_ip} → ${data.data.dst_ip} [${data.data.category}]`);
  }

  if (data.type === "alert") {
    console.warn(`🚨 ALERT: ${data.data.type} — ${data.data.detail}`);
  }
};

ws.onclose = () => console.log("🔌 Disconnected");
```

### Message Types

| Type | When it's sent |
|------|---------------|
| `connected` | Immediately after your WebSocket connects |
| `packet` | Every time a new packet is captured |
| `pong` | In response to a `{"action": "ping"}` message |

---

## Docker Setup

### Step 1 — Install Docker Desktop

Download from [docker.com](https://www.docker.com/products/docker-desktop/) and install. On Windows, follow the WSL 2 setup prompt.

Verify installation:
```bash
docker --version
docker run hello-world
```

### Step 2 — Build the Image

```bash
docker build -t ids-app .
```

This reads the `Dockerfile` and creates a self-contained image with Python, Scapy, and your code.

### Step 3 — Run the Container

```bash
docker run --privileged -p 8000:8000 --rm --name ids ids-app
```

| Flag | Meaning |
|------|---------|
| `--privileged` | Grants packet capture permissions to Scapy |
| `-p 8000:8000` | Maps port 8000 on your machine to the container |
| `--rm` | Automatically removes the container when stopped |
| `--name ids` | Gives the container a readable name |

### Step 4 — Test It

```bash
curl http://localhost:8000/
# or open http://localhost:8000/docs in your browser
```

### Step 5 — Stop It

Press `Ctrl+C` in the terminal. The `--rm` flag removes the container automatically.

> ⚠️ **Note:** On Windows and Mac, Docker runs inside a Linux VM. Scapy captures traffic within that VM — not your host machine's traffic. For full host network capture, run the app locally instead.

### Useful Docker Commands

```bash
docker ps                  # List running containers
docker images              # List all images
docker logs -f ids         # Follow live container logs
docker exec -it ids bash   # Open a shell inside the container
docker stop ids            # Stop the container
docker rmi ids-app         # Delete the image
```

---

## How It Works

### Traffic Classification (`classifier.py`)

Every network service uses a numbered "port". The classifier checks a packet's source and destination ports against known port lists:

| Category | Ports |
|----------|-------|
| `video` | 1935 (RTMP), 554 (RTSP), 8554 |
| `music` | 4070 (Spotify), 57621 |
| `normal_browsing` | 80 (HTTP), 443 (HTTPS), 53 (DNS) |
| `other` | Anything else |

### ARP Spoofing Detection (`detector.py`)

ARP (Address Resolution Protocol) maps IP addresses to MAC addresses on your local network. The detector builds a table of `IP → MAC` mappings. If an IP address suddenly claims a different MAC address, it flags a potential ARP spoofing attack.

### Credential Leak Detection (`detector.py`)

Scans TCP packets going to port 80 (plain HTTP — unencrypted) for keywords like `password=`, `login=`, `Authorization:`. HTTPS traffic is encrypted and cannot be read, so only unprotected HTTP traffic is checked.

### Real-Time WebSocket (`main.py`)

When `sniffer.py` processes a packet, it calls a callback function registered by `main.py`. That callback uses FastAPI's `ConnectionManager` to push the packet as JSON to all connected WebSocket clients instantly — no polling required.

---

## Testing the Endpoints

### Using the Built-in Docs (Recommended)

Visit `http://localhost:8000/docs` — FastAPI generates a full interactive UI automatically.

### Using curl

```bash
# Start capturing
curl -X POST http://localhost:8000/start

# Get recent packets
curl http://localhost:8000/packets

# Filter by category
curl http://localhost:8000/filter/normal_browsing

# Get alerts
curl http://localhost:8000/alerts

# Check status
curl http://localhost:8000/status

# Stop capturing
curl -X POST http://localhost:8000/stop
```

---

## Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** this repository on GitHub
2. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** and commit:
   ```bash
   git add .
   git commit -m "Add: description of your change"
   ```
4. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
5. Open a **Pull Request** on GitHub

### Ideas for Contributions

- Add more attack detection patterns (port scanning, SYN flood)
- Add a simple frontend dashboard
- Add persistent storage with SQLite
- Improve traffic classification with more port mappings
- Add email or desktop notifications for alerts

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

<div align="center">
  Built with ❤️ using FastAPI + Scapy + Python
  <br>
  <sub>A beginner-friendly project for learning Python backend development</sub>
</div>