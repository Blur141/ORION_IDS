<p align="center">
  <h1 align="center">🛡️ ORION IDS</h1>
  <p align="center"><strong>Real-Time Packet Classification & Intrusion Detection System</strong></p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python" />
    <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi" />
    <img src="https://img.shields.io/badge/Scapy-Packet%20Sniffing-orange?style=flat-square" />
    <img src="https://img.shields.io/badge/WebSocket-RealTime-brightgreen?style=flat-square" />
    <img src="https://img.shields.io/badge/Docker-Supported-2496ED?style=flat-square&logo=docker" />
  </p>
</p>

---

## 📌 Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Tech Stack](#tech-stack)
* [Project Structure](#project-structure)
* [How It Works](#how-it-works)
* [Installation & Setup](#installation--setup)
* [Running the Project](#running-the-project)
* [API Endpoints](#api-endpoints)
* [WebSocket (Live Data)](#websocket-live-data)
* [Docker Setup](#docker-setup)
* [Limitations](#limitations)
* [Future Improvements](#future-improvements)
* [Contributing](#contributing)
* [License](#license)

---

## 🚀 Overview

**ORION IDS** is a beginner-friendly **Intrusion Detection System (IDS)** built using Python.

It captures live network traffic, classifies it into categories like **video, music, and normal browsing**, and detects basic security threats such as:

* ARP spoofing
* Credential leaks (HTTP)

The system provides both:

* REST API (for control & data)
* WebSocket (for real-time monitoring)

---

## ✨ Features

* 📡 Real-time packet capture using Scapy
* 🧠 Smart traffic classification (video, music, browsing)
* 🌐 DNS-based detection for modern encrypted traffic
* 🚨 Attack detection (ARP spoofing, credential leaks)
* 🔁 Start/Stop control via API
* 📊 Packet filtering by category
* ⚡ Live updates using WebSocket
* 📝 Connection logging (IP, endpoint, timestamp)
* 🐳 Docker support (simulation mode)

---

## 🛠 Tech Stack

* **Backend:** FastAPI
* **Packet Capture:** Scapy
* **Real-time:** WebSocket
* **Language:** Python
* **Containerization:** Docker

---

## 📁 Project Structure

```
ids_project/
│
├── main.py        # FastAPI app (routes + WebSocket)
├── sniffer.py     # Packet capture logic
├── classifier.py  # Traffic classification
├── detector.py    # Attack detection
├── storage.py     # Store packets & alerts
├── state.py       # Start/Stop state
│
├── requirements.txt
├── Dockerfile
└── README.md
```

---

## 🧠 How It Works

1. Start the system using `/start`
2. Packets are captured using Scapy
3. DNS responses are used to map IP → category
4. Traffic is classified:

   * video
   * music
   * normal browsing
5. Packets are stored in memory
6. Alerts are generated for suspicious activity
7. Data is:

   * Available via API
   * Streamed live via WebSocket

---

## ⚙️ Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/ORION_IDS.git
cd ORION_IDS/ids_project
```

---

### 2. Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Install Npcap (IMPORTANT for Windows)

Download: https://npcap.com

✔ Enable **WinPcap compatibility mode**

---

## ▶️ Running the Project

Run (as Administrator):

```bash
python -m uvicorn main:app --reload
```

Open:

```
http://127.0.0.1:8000/docs
```

---

## 🔗 API Endpoints

| Method | Endpoint             | Description      |
| ------ | -------------------- | ---------------- |
| GET    | `/`                  | Health check     |
| POST   | `/start`             | Start capture    |
| POST   | `/stop`              | Stop capture     |
| GET    | `/packets`           | Get packets      |
| GET    | `/alerts`            | Get alerts       |
| GET    | `/filter/{category}` | Filter packets   |
| GET    | `/connections`       | View access logs |
| GET    | `/status`            | System status    |

---

## ⚡ WebSocket (Live Data)

Endpoint:

```
ws://127.0.0.1:8000/ws
```

Example (Browser Console):

```javascript
const ws = new WebSocket("ws://127.0.0.1:8000/ws");

ws.onmessage = (event) => {
  console.log("LIVE:", JSON.parse(event.data));
};
```

✔ Streams live packets and alerts
✔ No refresh required

---

## 🐳 Docker Setup

```bash
docker build -t orion-ids .
docker run -p 8000:8000 orion-ids
```

⚠️ Note:

* Docker runs in **simulation mode**
* For real packet capture → run locally

---

## ⚠️ Limitations

* HTTPS traffic cannot be inspected (encrypted)
* Classification depends on DNS mapping
* Docker cannot capture real host traffic
* Logs are stored in memory (not persistent)

---

## 🚀 Future Improvements

* 🎨 Frontend dashboard (React.js)
* 💾 Database storage (SQLite/PostgreSQL)
* 🌍 GeoIP tracking
* 📊 Real-time graphs
* 🔐 Advanced attack detection (DDoS, port scan)
* 📱 Notifications (email/alerts)

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repo
2. Create a branch
3. Make changes
4. Submit a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.

---

<p align="center">
  Built with ❤️ using FastAPI, Scapy & WebSockets  
</p>
