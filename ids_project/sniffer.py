# ============================================================
# sniffer.py — Live Packet Capture using Scapy
# ============================================================
# This file:
#   1. Captures live network packets from your machine
#   2. Extracts useful info (IPs, ports, protocol, size)
#   3. Classifies the traffic (video / music / browsing)
#   4. Runs attack detectors on each packet
#   5. Saves everything to storage
#   6. Broadcasts live data to WebSocket clients
# ============================================================

import datetime
import asyncio
import threading

from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import sniff as scapy_sniff

import ids_project.storage as storage
import ids_project.classifier as classifier
import ids_project.detector as detector
from ids_project.state import sniffer_state

# -----------------------------------------------------------
# WebSocket broadcast hook
# -----------------------------------------------------------
# main.py will set this to a real function that sends data
# to all connected WebSocket clients.
# We start it as None and check before calling.
broadcast_callback = None


def set_broadcast_callback(fn):
    """Called from main.py to register the WebSocket broadcaster."""
    global broadcast_callback
    broadcast_callback = fn


# -----------------------------------------------------------
# Process a single packet
# -----------------------------------------------------------
def process_packet(packet):
    """
    This function is called by Scapy for EVERY captured packet.
    Think of it like an event handler — Scapy fires it automatically.
    """

    # ── Only process packets that have an IP layer ──────────
    # Many network frames (like ARP) don't have IP. We handle
    # ARP separately in detector.py — here we skip non-IP.
    # BUT we still run detectors so ARP detection works!
    detector.run_detectors(packet)

    if not packet.haslayer(IP):
        return   # skip non-IP packets for storage

    ip_layer = packet[IP]
    src_ip   = ip_layer.src
    dst_ip   = ip_layer.dst
    size     = len(packet)           # total packet size in bytes
    proto    = "OTHER"
    src_port = 0
    dst_port = 0

    # ── Determine protocol and extract ports ─────────────────
    if packet.haslayer(TCP):
        proto    = "TCP"
        src_port = packet[TCP].sport  # source port (random high number)
        dst_port = packet[TCP].dport  # destination port (service port)
    elif packet.haslayer(UDP):
        proto    = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # ── Classify the traffic ──────────────────────────────────
    category = classifier.classify_packet(src_port, dst_port)

    # ── Build packet summary dict ─────────────────────────────
    packet_summary = {
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  proto,
        "category":  category,
        "size":      size,
        "timestamp": datetime.datetime.now().isoformat()
    }

    # ── Save to storage ───────────────────────────────────────
    storage.add_packet(packet_summary)

    # ── Broadcast to WebSocket clients ────────────────────────
    # We schedule the async broadcast from this sync thread
    if broadcast_callback:
        try:
            asyncio.run(broadcast_callback({"type": "packet", "data": packet_summary}))
        except Exception:
            pass   # WebSocket errors shouldn't crash the sniffer


# -----------------------------------------------------------
# Packet capture loop (runs in a background thread)
# -----------------------------------------------------------
def _capture_loop():
    """
    Runs Scapy's sniffer in a loop until sniffer_state["running"]
    becomes False.

    scapy_sniff() parameters explained:
      prn       = function to call for EACH packet (our process_packet)
      store     = False → don't store packets in Scapy's memory (saves RAM)
      timeout   = 1 → stop every 1 second to check if we should keep going
                  (this is how we detect the /stop command)
      count     = 0 → capture unlimited packets per batch
    """
    while sniffer_state["running"]:
        scapy_sniff(
            prn=process_packet,
            store=False,
            timeout=1,      # re-checks sniffer_state every 1 second
            count=0
        )


# -----------------------------------------------------------
# Public: start the sniffer in a background thread
# -----------------------------------------------------------
def start_sniffer():
    """
    Starts packet capture in a DAEMON thread.
    A daemon thread automatically dies when the main program exits.
    """
    sniffer_state["running"] = True
    storage.clear_all()   # fresh start: clear old data

    thread = threading.Thread(target=_capture_loop, daemon=True)
    thread.start()
    return thread


# -----------------------------------------------------------
# Public: stop the sniffer
# -----------------------------------------------------------
def stop_sniffer():
    """
    Sets the running flag to False.
    The _capture_loop() will see this on its next timeout check
    and stop naturally (within ~1 second).
    """
    sniffer_state["running"] = False
