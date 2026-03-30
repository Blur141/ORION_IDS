# 🧠 Real-Time Packet Classification & IDS (FastAPI)

This project is a Real-Time Network Intrusion Detection System (IDS) built using Python and FastAPI.

It captures live network packets, classifies traffic (video, music, normal browsing), and detects suspicious activities like ARP spoofing and credential leaks.

---

## 🚀 Features

* 📡 Real-time packet sniffing
* 🧠 Traffic classification (Video, Music, Normal Browsing)
* 🚨 Attack detection:

  * ARP Spoofing
  * Credential leaks
* 🔴 Live monitoring support (WebSocket ready)
* ▶ Start / Stop control via API

---

## 🛠 Requirements

* Python 3.10+
* pip
* Npcap (for Windows packet capture)

---

## ⚠️ IMPORTANT (Windows Users)

Install Npcap before running:

https://npcap.com

✔ Install with:

* WinPcap compatibility mode

---

## 📦 Installation

### 1. Clone Repository

```bash
git clone https://github.com/Blur141/ORION_IDS.git
cd ORION_IDS/realtime_ids_backend
```

---

### 2. Create Virtual Environment

```bash
python -m venv venv
```

---

### 3. Activate Virtual Environment

#### Windows:

```bash
venv\Scripts\activate
```

#### Linux / Mac:

```bash
source venv/bin/activate
```

---

### 4. Install Dependencies

```bash
pip install fastapi uvicorn scapy
```

---

## ▶️ Run the Application

```bash
python -m uvicorn main:app --reload
```

---

## 🌐 Access API

Open in browser:

http://127.0.0.1:8000/docs

---

## 🎮 How to Use

### ▶ Start IDS

Use: POST /start

### ⏹ Stop IDS

Use: POST /stop

### 📊 View Packets

Use: GET /packets

### 🚨 View Alerts

Use: GET /alerts

### 🎯 Filter Traffic

* /filter/video
* /filter/music
* /filter/normal browsing

---

## 🧠 How It Works

1. Scapy captures live packets
2. Packets are classified using:

   * DNS queries
   * Ports
3. Detection engine checks for:

   * ARP spoofing
   * Credential leaks
4. Data is exposed via FastAPI APIs

---

## ⚠️ Limitations

* Cannot see exact video/content due to HTTPS encryption
* Classification is based on metadata (DNS, ports)

---

## 📌 Future Improvements

* Web dashboard (React)
* Machine Learning-based detection
* Database storage
* Advanced traffic analysis

---

## 👨‍💻 Author

Mohammed Niyas

---

## ⭐ If you like this project, give it a star!
