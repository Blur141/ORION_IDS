from fastapi import FastAPI
import threading

from sniffer import start_sniffing
import state
from storage import packets, alerts

app = FastAPI()

sniffer_thread = None

@app.get("/")
def home():
    return {"status": "IDS Backend Running"}

# ▶ START
@app.post("/start")
def start():
    global sniffer_thread

    if state.is_running:
        return {"message": "Already running"}

    state.is_running = True

    sniffer_thread = threading.Thread(target=start_sniffing)
    sniffer_thread.start()

    return {"message": "Sniffer started"}

# ⏹ STOP
@app.post("/stop")
def stop():
    state.is_running = False
    return {"message": "Sniffer stopped"}

# 📊 GET PACKETS
@app.get("/packets")
def get_packets():
    return packets[-50:]

# 🚨 GET ALERTS
@app.get("/alerts")
def get_alerts():
    return alerts[-50:]

# 🎯 FILTER
@app.get("/filter/{category}")
def filter_packets(category: str):
    return [p for p in packets if p["category"] == category]