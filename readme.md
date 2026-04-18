# 🛡️ NetGuard IDS

**A real-time Network Intrusion Detection System with a live web dashboard.**

NetGuard captures every packet on your network interface — exactly like Wireshark — analyzes them for threats using a stateful rule-based engine, and streams everything live to a React dashboard over WebSocket. It identifies 80+ services (YouTube, WhatsApp, Google Meet, Netflix, Discord, etc.), categorizes traffic into 14 types, and fires precise security alerts without false-positive noise.

![Dashboard Screenshot](netguard-ids/docs/Dashboard1.png)
![Dashboard Screenshot](netguard-ids/docs/Dashboard2.png)
![Dashboard Screenshot](netguard-ids/docs/Dashboard3.png)


---

## ✨ Features

- **Wireshark-grade live capture** — Scapy in promiscuous mode, all protocols (TCP, UDP, ICMP, ARP, DNS, HTTP, HTTPS, IPv6)
- **TLS SNI extraction** — identifies HTTPS destinations without decrypting traffic
- **Service identification** — 5-tier resolution: TLS SNI → DNS query → reverse DNS → IP prefix → port
- **80+ known services** — Google, YouTube, WhatsApp, Netflix, Spotify, Discord, Slack, Zoom, GitHub, and more
- **14 traffic categories** — Streaming, Social, VoIP, Messaging, Cloud/CDN, DNS, LAN/Local, Security, and more
- **9 attack detectors** — ARP Spoofing, SYN Flood, Port Scan, ICMP Flood, DNS Tunneling, Credential Leakage, Brute Force, Low TTL Anomaly, Sensitive Port Access
- **Zero false-positive design** — Docker, NTP, mDNS, SSDP and other benign LAN protocols are never flagged
- **WebSocket live feed** — sub-100ms packet streaming to the browser
- **REST API** — query events, alerts, stats, and analytics
- **SQLite persistence** — all packets and alerts stored for historical queries
- **Simulation mode** — works without root/Scapy for UI development
- **Start / Stop / Reset** controls from the dashboard

---

## 🗂️ Project Structure

```
netguard-ids/
├── backend/
│   ├── main.py                  # FastAPI app — REST API + WebSocket server
│   ├── core/
│   │   ├── capture.py           # Scapy packet capture engine
│   │   ├── detector.py          # Rule-based threat detection engine
│   │   └── engine.py            # Orchestration — capture → detect → broadcast
│   └── db/
│       └── database.py          # SQLAlchemy async DB models + session
│
└── frontend/
    └── src/
        ├── App.jsx              # Main React UI — tabs, table, alerts, charts
        ├── App.css              # Dark theme styles
        ├── index.js             # React entry point
        ├── hooks/
        │   └── useIDSWebSocket.js   # WebSocket hook with throttling + reconnect
        └── utils/
            ├── serviceResolver.js   # 5-tier service identification
            └── classifier.js        # 14-category traffic classifier
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| Node.js | 18+ |
| Scapy | `pip install scapy` |
| Root / Admin | Required for raw socket capture |

### 1 — Backend

```bash
cd backend

# Install dependencies
pip install fastapi uvicorn sqlalchemy aiosqlite scapy

# Run with root (required for live capture)
sudo uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

> **Windows:** Run your terminal as Administrator instead of `sudo`.

### 2 — Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm start
```

Open [http://localhost:3000](http://localhost:3000) — the dashboard connects automatically.

---

## ⚙️ Configuration

### Environment Variables (Frontend)

Create a `.env` file in `frontend/`:

```env
REACT_APP_WS_URL=ws://localhost:8000/ws
REACT_APP_API_URL=http://localhost:8000
```

### Network Interface

The backend auto-detects the best interface (Wi-Fi preferred over Ethernet, virtual interfaces excluded). To override:

```python
# in backend/main.py
ids_engine = IDSEngine(interface="eth0")   # Linux
ids_engine = IDSEngine(interface="en0")    # macOS
ids_engine = IDSEngine(interface="Wi-Fi")  # Windows
```

To list all available interfaces:

```python
from core.capture import get_available_interfaces
print(get_available_interfaces())
```

### BPF Filter

To exclude noisy traffic (e.g. SSH connections to your own machine):

```python
# in backend/core/engine.py → PacketCapture(...)
PacketCapture(interface=best_iface, bpf_filter="not port 22")
```

---

## 📡 How It Works

### Capture Pipeline

```
Network Interface (promiscuous mode)
        │
        ▼
  Scapy sniff()  ──────────────────────── daemon thread
        │
        ▼
  _parse_packet()   ← extracts IP, TCP/UDP, DNS, ARP, TLS SNI, HTTP payload
        │
        ▼
  Queue (10,000 packet buffer)
        │
        ▼
  process_loop()    ← async consumer
        │
        ├──► DetectionEngine.analyze()   → DetectionResult (severity + attack type)
        │
        ├──► WebSocket broadcast         → React dashboard (real-time)
        │
        └──► SQLite persist              → historical queries via REST API
```

### Service Resolution (5-Tier)

For every packet, `serviceResolver.js` tries in order:

1. **TLS SNI** — extracted from the raw ClientHello bytes; identifies HTTPS destinations with 100% accuracy
2. **DNS query** — identifies the domain being looked up; covers DNS traffic before the connection
3. **Reverse-DNS hostname** — `src_hostname` / `dst_hostname` from OS resolver cache
4. **IP prefix** — maps known CDN/cloud IP ranges (Google `142.250.x`, Cloudflare `104.16.x`, Apple `17.x`, etc.)
5. **Port** — last resort fallback (e.g. port 443 → HTTPS, port 22 → SSH)

### Traffic Categories (14 Types)

| Category | Examples |
|----------|---------|
| 🎬 Streaming | YouTube, Netflix, Spotify, Twitch, Disney+ |
| 👥 Social | Facebook, Instagram, Twitter/X, Reddit, LinkedIn |
| 📹 VoIP / Video | Google Meet, Zoom, Discord, MS Teams, Skype |
| 💬 Messaging | WhatsApp, Telegram, Signal, Slack |
| ☁️ Cloud / CDN | AWS, Cloudflare, Akamai, Fastly, iCloud |
| 🌐 Web Browsing | Unknown HTTPS/HTTP to external IPs |
| ⚙️ System / OS | Windows Update, Apple telemetry, NTP, analytics |
| 🔍 DNS | DNS queries and responses |
| 🏠 LAN / Local | ARP, mDNS, SSDP, SMB, Docker internal |
| 🔐 Security / VPN | VPN services, PKI/OCSP, IKE |
| 🗄️ Database | MySQL, PostgreSQL, Redis, MongoDB |
| 🛠️ Dev Tools | GitHub, SSH, npm, GitLab, Claude AI |
| ❓ Other | Unclassified traffic |

### Threat Detectors

| Detector | Trigger | Severity |
|----------|---------|----------|
| **ARP Spoofing** | IP→MAC mapping changes | Malicious |
| **SYN Flood** | ≥100 SYN packets/sec from same IP | Malicious |
| **Port Scan** | ≥20 unique ports probed (external→external) | Suspicious / Malicious |
| **ICMP Flood** | ≥50 ICMP packets/sec from same IP | Malicious |
| **DNS Tunneling** | ≥30 DNS queries/sec from same IP | Suspicious |
| **DNS Anomaly** | DGA patterns, high-risk TLDs, C2 keywords | Suspicious |
| **Credential Leakage** | Passwords / API keys in plaintext HTTP | Malicious |
| **Brute Force** | ≥15 SYNs to auth port (external source) | Malicious |
| **Low TTL Anomaly** | TCP TTL ≤ 3 from external IP | Suspicious |
| **Sensitive Port Access** | External IP connecting to backdoor ports | Suspicious / Malicious |

#### False Positive Prevention

A major design goal is **zero noise from legitimate traffic**:

- TTL anomaly fires **only on TCP** — NTP, mDNS, SSDP, and Docker all use TTL=1 on UDP legitimately
- Port scan skips **LAN→LAN** — SMB discovery, Bonjour, and printer detection are normal
- Brute force only flags **external source IPs** — local SSH/DB access is expected
- Sensitive port alerts exclude **80+ benign ports** (DNS/53, NTP/123, DHCP/67-68, SSDP/1900, etc.)
- DNS anomaly has an **extensive whitelist** of known-safe domains + `.local`, `.internal`, `.lan` suffixes
- ARP anomaly ignores **Docker virtual MAC prefixes** (`02:xx`, `0a:xx`, `52:xx`)

---

## 🔌 REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/status` | Engine status + current stats |
| `GET` | `/api/stats` | Packet counts, bandwidth, protocol distribution |
| `GET` | `/api/events` | Recent network events (filterable by severity, protocol, IP) |
| `GET` | `/api/alerts` | Security alerts (filterable by severity, acknowledged) |
| `PATCH` | `/api/alerts/{id}/acknowledge` | Acknowledge an alert |
| `GET` | `/api/analytics/timeline` | Severity counts over last N hours |
| `POST` | `/api/control/start` | Start packet capture |
| `POST` | `/api/control/stop` | Stop packet capture |
| `POST` | `/api/control/reset` | Reset all counters and buffers |
| `WS` | `/ws` | Live WebSocket stream (packets, alerts, stats) |

### WebSocket Message Types

```jsonc
// Server → Client
{ "type": "init",   "data": { "recent_packets": [...], "recent_alerts": [...], "stats": {...} } }
{ "type": "packet", "data": { "src_ip": "...", "dst_ip": "...", "protocol": "HTTPS", ... } }
{ "type": "alert",  "data": { "alert_type": "Port Scan", "severity": "suspicious", ... } }
{ "type": "stats",  "data": { "total_packets": 12400, "bandwidth_bps": 204800, ... } }
{ "type": "ping" }
```

---

## 🖥️ Dashboard

### Live Feed Tab
- Real-time packet table with time, protocol, source, destination, service badge, size, severity, attack type, and category
- Search across all fields (IP, hostname, service name, protocol, attack type)
- Filter by category (14 types) and severity
- Color-coded rows: yellow border = suspicious, red border = malicious

### Alerts Tab
- All security alerts in a card grid
- One-click acknowledge per alert
- Unacknowledged count shown in tab badge

### Analytics Tab
- **Traffic Timeline** — rolling bandwidth chart (KB/s over last 30 samples)
- **Threat Activity** — stacked bar chart of Normal / Suspicious / Malicious counts
- **Protocol Mix** — donut chart of protocol distribution
- **Top Source IPs** — horizontal bar chart of most active sources

---

## 🛠️ Development

### Running Without Root (Simulation Mode)

If Scapy is not installed or you lack root privileges, the engine automatically falls back to simulation mode — generating realistic synthetic traffic so the UI stays fully usable during development.

```bash
# No sudo needed — simulation kicks in automatically
uvicorn main:app --reload
```

The mode badge in the top-right corner of the dashboard shows `live` or `simulation`.

### Adding a New Service

Edit `frontend/src/utils/serviceResolver.js` — add an entry to `DOMAIN_MAP`:

```javascript
{ match: ["example.com", "cdn.example.com"], name: "Example", emoji: "🔥", color: "#FF6B6B" },
```

### Adding a New Detector

Edit `backend/core/detector.py` — implement a method and register it:

```python
def _check_my_attack(self, packet: dict) -> Optional[DetectionResult]:
    # your logic here
    return DetectionResult(severity="suspicious", attack_type="My Attack", description="...", score=70.0)

# Add to the detectors list in analyze():
detectors = [..., self._check_my_attack]
```

---

## 📦 Dependencies

### Backend

| Package | Purpose |
|---------|---------|
| `fastapi` | REST API + WebSocket server |
| `uvicorn` | ASGI server |
| `sqlalchemy` | Async ORM |
| `aiosqlite` | Async SQLite driver |
| `scapy` | Raw packet capture |

### Frontend

| Package | Purpose |
|---------|---------|
| `react` | UI framework |
| `recharts` | Charts (area, bar, pie) |
| `lucide-react` | Icon set |

---

## 🔒 Security & Privacy Notes

- **Root privileges** are required for raw socket capture. Always run in a trusted environment.
- **No traffic is sent externally** — all capture and analysis happens locally.
- **HTTP payloads** are inspected for credential leakage but never stored in full — only the first 800 bytes are kept in memory for detection, not persisted to the database.
- **TLS/HTTPS traffic is not decrypted** — only the SNI hostname (sent in plaintext during the TLS handshake) is extracted.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) — the engine behind live packet capture
- [FastAPI](https://fastapi.tiangolo.com/) — the backend framework
- [Recharts](https://recharts.org/) — dashboard charts
- [Lucide](https://lucide.dev/) — dashboard icons