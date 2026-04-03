# ============================================================
# storage.py — In-Memory Storage for Packets & Alerts
# ============================================================
# Think of this as our "database" — but stored in RAM.
# When the app restarts, data is cleared (that's fine for learning).
# ============================================================

from collections import deque  # deque = a list with a max size limit
import datetime

# -----------------------------------------------------------
# Storage containers
# -----------------------------------------------------------

# deque(maxlen=500) means: keep the last 500 items only.
# When item 501 arrives, item 1 is automatically removed.
packets = deque(maxlen=500)   # stores packet summaries
alerts  = deque(maxlen=200)   # stores attack/threat alerts


# -----------------------------------------------------------
# Helper: add a packet
# -----------------------------------------------------------
def add_packet(packet_dict: dict):
    """
    Save one packet summary to storage.
    packet_dict should look like:
    {
        "src_ip": "192.168.1.5",
        "dst_ip": "8.8.8.8",
        "protocol": "TCP",
        "category": "normal_browsing",
        "size": 60,
        "timestamp": "2024-01-01T12:00:00"
    }
    """
    packets.append(packet_dict)


# -----------------------------------------------------------
# Helper: add an alert
# -----------------------------------------------------------
def add_alert(alert_dict: dict):
    """
    Save one alert to storage.
    alert_dict should look like:
    {
        "type": "ARP Spoofing",
        "detail": "IP 192.168.1.1 has two MACs",
        "timestamp": "2024-01-01T12:00:00"
    }
    """
    alerts.append(alert_dict)


# -----------------------------------------------------------
# Helper: get all packets as a plain list
# -----------------------------------------------------------
def get_packets(category: str = None):
    """
    Return all stored packets.
    If category is given, return only packets of that category.
    """
    all_packets = list(packets)
    if category:
        return [p for p in all_packets if p.get("category") == category]
    return all_packets


# -----------------------------------------------------------
# Helper: get all alerts as a plain list
# -----------------------------------------------------------
def get_alerts():
    return list(alerts)


# -----------------------------------------------------------
# Helper: clear everything (used on /start to reset)
# -----------------------------------------------------------
def clear_all():
    packets.clear()
    alerts.clear()
