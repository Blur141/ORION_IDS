# 🛡️ NetGuard IDS — Real-Time Intrusion Detection System

A production-ready, real-time network Intrusion Detection System built with Python, FastAPI, Scapy, WebSockets, and React.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetGuard IDS                             │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  Scapy       │    │  Detection   │    │  FastAPI         │  │
│  │  Packet      │───▶│  Engine      │───▶│  REST + WS       │  │
│  │  Capture     │    │  (8 rules)   │    │  Backend         │  │
│  └──────────────┘    └──────────────┘    └────────┬─────────┘  │
│         │                   │                     │            │
│  Live / Simulated     SQLite DB             WebSocket          │
│  Network Traffic      Persistence           Broadcast          │
│                                                  │             │
│                                        ┌─────────▼──────────┐  │
│                                        │  React Dashboard   │  │
│                                        │  Live Feed         │  │
│                                        │  Alerts Panel      │  │
│                                        │  Analytics Charts  │  │
│                                        └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
ids-project/
├── backend/
│   ├── main.py                  # FastAPI app — REST API + WebSocket
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── core/
│   │   ├── capture.py           # Scapy packet capture engine
│   │   ├── detector.py          # Detection rules (8 attack types)
│   │   └── engine.py            # Orchestrator — ties everything together
│   └── db/
│       └── database.py          # SQLAlchemy models + async SQLite
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main dashboard — 3 tabs
│   │   ├── App.css              # Dark cybersecurity aesthetic
│   │   ├── index.js
│   │   └── hooks/
│   │       └── useIDSWebSocket.js  # Real-time WS data hook
│   ├── public/index.html
│   ├── package.json
│   ├── Dockerfile
│   └── nginx.conf
│
├── docker-compose.yml
└── README.md
```

---

## 🔍 Detected Attack Types

| Attack               | Method                                      | Severity    |
|----------------------|---------------------------------------------|-------------|
| **ARP Spoofing**     | IP→MAC mapping change detection             | Malicious   |
| **Port Scan**        | SYN-only packets to 15+ unique ports        | Malicious   |
| **SYN Flood**        | 50+ SYN/sec from single source              | Malicious   |
| **Brute Force**      | 10+ connection attempts in 5s to auth port  | Malicious   |
| **Credential Leak**  | Plaintext passwords/API keys in HTTP        | Malicious   |
| **ICMP Flood**       | 30+ ICMP packets/sec from single source     | Malicious   |
| **DNS Tunneling**    | High DNS query rate (20+/sec)               | Suspicious  |
| **DNS Anomaly**      | DGA-like domains, high-risk TLDs            | Suspicious  |
| **Low TTL**          | TTL ≤ 5 (spoofed/tunneled packets)          | Suspicious  |
| **Sensitive Ports**  | Access to SSH, RDP, DB, backdoor ports      | Suspicious  |

---

## 🚀 Quick Start

### Option 1 — Docker (Recommended)

```bash
git clone https://github.com/your-org/ids-project
cd ids-project

# Start everything
docker-compose up --build

# Dashboard: http://localhost:3000
# API:       http://localhost:8000
# API Docs:  http://localhost:8000/docs
```

> **Note:** Live packet capture requires `--privileged` or the `NET_RAW` + `NET_ADMIN` capabilities (already set in docker-compose.yml). Without root, the system auto-falls back to simulation mode.

---

### Option 2 — Manual Setup

#### Backend

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run (simulation mode, no root required)
uvicorn main:app --reload --port 8000

# Run with live capture (requires root/sudo)
sudo uvicorn main:app --reload --port 8000
```

#### Frontend

```bash
cd frontend
npm install
npm start          # Opens http://localhost:3000
```

---

## 📡 API Reference

### REST Endpoints

| Method | Endpoint                          | Description                        |
|--------|-----------------------------------|------------------------------------|
| GET    | `/api/status`                     | Engine status + live stats         |
| GET    | `/api/stats`                      | Packet counts, protocol mix        |
| GET    | `/api/events?limit=100`           | Recent network events from DB      |
| GET    | `/api/events?severity=malicious`  | Filter events by severity          |
| GET    | `/api/alerts?unacknowledged=true` | Get unacknowledged alerts          |
| PATCH  | `/api/alerts/{id}/acknowledge`    | Acknowledge an alert               |
| GET    | `/api/analytics/timeline?hours=1` | Severity counts over time          |
| POST   | `/api/control/start`              | Start capture engine               |
| POST   | `/api/control/stop`               | Stop capture engine                |

All docs available at `http://localhost:8000/docs` (Swagger UI).

---

### WebSocket — `ws://localhost:8000/ws`

Clients receive three message types:

```jsonc
// On connect: full initial state
{ "type": "init",   "data": { "recent_packets": [...], "recent_alerts": [...], "stats": {...} } }

// Every packet processed
{ "type": "packet", "data": { "src_ip": "...", "dst_ip": "...", "severity": "info", ... } }

// New alert (rate-limited: max 1 per 10s per IP+type)
{ "type": "alert",  "data": { "alert_type": "SYN Flood", "severity": "malicious", ... } }

// Stats broadcast every 2 seconds
{ "type": "stats",  "data": { "total_packets": 1234, "bandwidth_bps": 45000, ... } }
```

---

## 🖥️ Dashboard Tabs

### 1. Live Feed
- Real-time scrolling packet table (protocol, src/dst IP:port, size, severity, attack type)
- Filter by severity: All / Normal / Suspicious / Malicious
- Inline alert panel with acknowledge button

### 2. Alerts
- Full alert log grid
- Color-coded by severity (red = malicious, yellow = suspicious)
- One-click acknowledge

### 3. Analytics
- **Traffic Timeline** — bandwidth KB/s over rolling 30-point window
- **Threat Activity** — stacked bar chart of Normal/Suspicious/Malicious
- **Protocol Mix** — donut chart of traffic breakdown
- **Top Source IPs** — ranked bar chart

---

## ⚙️ Capture Modes

| Mode           | When                                         | Notes                        |
|----------------|----------------------------------------------|------------------------------|
| **Live**       | Root/admin + Scapy installed + interface up  | Captures real network traffic |
| **Simulation** | No root, or Scapy unavailable                | Generates realistic synthetic traffic including injected attack patterns |

The system detects privileges automatically and falls back gracefully. You will see the mode label ("live" / "simulation") in the dashboard header.

---

## 🔧 Configuration

Set via environment variables or `.env`:

```env
# Backend
IDS_INTERFACE=eth0          # Network interface (default: system default)
IDS_DB_URL=sqlite+aiosqlite:///./ids_events.db

# Frontend
REACT_APP_WS_URL=ws://localhost:8000/ws
REACT_APP_API_URL=http://localhost:8000
```

---

## 🧩 Extending the System

### Add a New Detector

Open `backend/core/detector.py` and add a method to `DetectionEngine`:

```python
def _check_my_attack(self, packet: dict) -> Optional[DetectionResult]:
    if packet.get("protocol") != "TCP":
        return None
    # Your detection logic here
    return DetectionResult(
        severity="suspicious",
        attack_type="My Attack",
        description="...",
        score=70.0,
    )
```

Then register it in the `analyze()` method's `detectors` list.

### Add Machine Learning

The `DetectionResult` includes a `score` (0–100) field. You can:

1. Log feature vectors (TTL, size, port, flag, rate) to a CSV.
2. Train a classifier (Random Forest, Isolation Forest for anomaly detection).
3. Replace or augment `_check_*` methods with model inference.

Suggested libraries: `scikit-learn`, `river` (online/streaming ML), `tensorflow`.

---

## 🔒 Security & Legal

- **Use only on networks you own or have explicit permission to monitor.**
- Live packet capture captures all traffic on the interface — handle data responsibly.
- In production, restrict WebSocket/API access with authentication (JWT, API keys).
- Consider encrypting the SQLite database in sensitive deployments.

---

## 📦 Tech Stack

| Layer      | Technology                        |
|------------|-----------------------------------|
| Capture    | Scapy 2.6                         |
| Backend    | Python 3.12, FastAPI, Uvicorn     |
| Real-time  | WebSockets (native FastAPI)       |
| Database   | SQLite + SQLAlchemy async         |
| Frontend   | React 18, Recharts, Lucide Icons  |
| Deploy     | Docker, Docker Compose, Nginx     |

---

## 🗺️ Roadmap

- [ ] JWT authentication for API/dashboard
- [ ] Email / Slack / webhook alert notifications
- [ ] Machine learning anomaly detection (Isolation Forest)
- [ ] PCAP file import and offline analysis
- [ ] GeoIP enrichment (MaxMind)
- [ ] Multi-interface support
- [ ] Grafana integration via Prometheus metrics
- [ ] Suricata rule import compatibility

---

## 📄 License

MIT — free to use, extend, and deploy.
