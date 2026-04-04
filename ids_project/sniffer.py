# ============================================================
# sniffer.py  ——  FINAL WORKING VERSION
# ============================================================
#
# ROOT CAUSE OF THE PERSISTENT PROBLEM
# ══════════════════════════════════════════════════════════
#
# Docker has a hard architectural wall:
#
#   Your Browser (Windows/Mac Host)
#       │
#       │  HTTPS to youtube.com  ← your real traffic lives HERE
#       │
#   [Host Network Stack]         ← traffic goes through here
#       │
#   [Docker Virtual Bridge]      ← Scapy can only see THIS layer
#       │
#   [Container: your app]        ← we run here, BELOW the wall
#
# No matter which interface we detect or how we configure Scapy,
# the container CANNOT reach up through the Docker bridge to see
# the host's browser traffic. It is a kernel-level isolation.
#
# THE REAL FIX:
# ══════════════════════════════════════════════════════════
# Stop using Docker for packet capture. Run with:
#   uvicorn main:app --reload --port 8000
# as Administrator (Windows) or sudo (Linux/Mac).
#
# WHAT THIS FILE DOES (works in BOTH modes):
# ══════════════════════════════════════════════════════════
# 1. Seeds DNS table on start (instant correct classification)
# 2. Tests if live capture actually works
# 3. If yes  -> live mode (real packets from your network)
# 4. If no   -> simulation mode (real IPs, realistic traffic)
#    Simulation uses the actual IPs of YouTube/Spotify/etc
#    so classification shows video/music/browsing correctly.
#
# ============================================================

import datetime
import asyncio
import threading
import socket
import time
import random

from scapy.layers.inet  import IP, TCP, UDP
from scapy.layers.dns   import DNS, DNSQR
from scapy.packet       import NoPayload
from scapy.sendrecv     import sniff as scapy_sniff

import storage
import classifier
import detector
from state import sniffer_state

# Global state
broadcast_callback = None
active_interface   = None
capture_mode       = "stopped"   # "live" | "simulation" | "stopped"


def set_broadcast_callback(fn):
    global broadcast_callback
    broadcast_callback = fn


# ============================================================
# PART 1 — DNS PRE-SEEDING
# ============================================================

def seed_dns_for_domain(domain: str) -> list:
    """
    Resolves a domain to IPs via Python socket and seeds the
    classifier table. Works inside Docker too.
    """
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list(set(r[4][0] for r in results))
        if ips:
            classifier.update_dns_table(domain, ips)
            print(f"  [Seed] {domain:40s} -> {ips}")
        return ips
    except Exception as e:
        print(f"  [Seed] FAILED {domain}: {e}")
        return []


def seed_common_services() -> int:
    """
    Seeds all major streaming service domains at startup.
    Returns the number of IPs mapped.
    """
    print("\n[Sniffer] Seeding DNS table with streaming service IPs...")

    video_domains = [
        "youtube.com", "googlevideo.com", "ytimg.com",
        "twitch.tv", "jtvnw.net", "twitchsvc.net",
        "netflix.com", "nflxvideo.net",
        "vimeo.com", "tiktok.com", "disneyplus.com",
        "hulu.com",
    ]
    music_domains = [
        "spotify.com", "scdn.co", "spotifycdn.com",
        "soundcloud.com", "sndcdn.com",
        "music.apple.com", "mzstatic.com",
        "deezer.com", "tidal.com",
    ]

    for d in video_domains:
        seed_dns_for_domain(d)
    for d in music_domains:
        seed_dns_for_domain(d)

    n = len(classifier.ip_category_table)
    print(f"[Sniffer] DNS seed complete. {n} IPs mapped.\n")
    return n


# ============================================================
# PART 2 — INTERFACE DETECTION
# ============================================================

def get_best_interface():
    """Finds the real internet-facing network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"[Sniffer] Outbound IP: {local_ip}")

        from scapy.interfaces import ifaces
        for name, iface in ifaces.items():
            if hasattr(iface, 'ip') and iface.ip == local_ip:
                print(f"[Sniffer] Selected interface: {name}")
                return name
    except Exception as e:
        print(f"[Sniffer] Interface detection error: {e}")
    return None


# ============================================================
# PART 3 — LIVE PACKET PROCESSING
# ============================================================

def process_dns_packet(packet):
    """Reads live DNS responses and updates the classifier table."""
    if not packet.haslayer(DNS):
        return
    dns = packet[DNS]
    if dns.qr != 1 or dns.ancount == 0 or not packet.haslayer(DNSQR):
        return
    try:
        domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
    except Exception:
        return

    resolved_ips = []
    answer = dns.an
    while answer and not isinstance(answer, NoPayload):
        try:
            if hasattr(answer, 'type') and answer.type == 1:
                ip = answer.rdata
                if isinstance(ip, bytes):
                    ip = socket.inet_ntoa(ip)
                if isinstance(ip, str):
                    resolved_ips.append(ip)
            answer = answer.payload
        except Exception:
            break

    if resolved_ips:
        print(f"[DNS Live] {domain} -> {resolved_ips}")
        classifier.update_dns_table(domain, resolved_ips)


def process_packet(packet):
    """Called by Scapy for every captured packet."""
    detector.run_detectors(packet)

    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    size = len(packet)
    proto = "OTHER"
    src_port = dst_port = 0

    if packet.haslayer(TCP):
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        if src_port == 53 or dst_port == 53:
            process_dns_packet(packet)

    category = classifier.classify_packet(src_ip, dst_ip, src_port, dst_port)

    _save_and_broadcast({
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  proto,
        "category":  category,
        "size":      size,
        "timestamp": datetime.datetime.now().isoformat(),
        "mode":      "live"
    })


# ============================================================
# PART 4 — SIMULATION MODE (automatic Docker fallback)
# ============================================================

def _simulation_loop():
    """
    Simulates network traffic using REAL IPs from the DNS table.

    Why this is useful:
      Inside Docker, real capture is impossible. But by using
      the actual IP addresses of YouTube/Spotify (resolved via
      DNS seeding), the classifier correctly labels simulated
      packets as video/music — proving the system works.

    Traffic mix: 30% video, 20% music, 35% browsing, 15% other
    """
    global capture_mode
    capture_mode = "simulation"

    video_ips  = [ip for ip, c in classifier.ip_category_table.items() if c == "video"]
    music_ips  = [ip for ip, c in classifier.ip_category_table.items() if c == "music"]

    # Hard fallbacks in case DNS failed
    if not video_ips:
        video_ips = ["142.250.80.46", "35.186.224.25", "151.101.1.63"]
    if not music_ips:
        music_ips = ["35.186.224.47", "104.154.127.10"]

    browsing_ips = ["8.8.8.8", "1.1.1.1", "172.217.14.196"]
    my_ip = "192.168.1." + str(random.randint(2, 30))

    # (weight, dst_pool, dst_ports, proto, size_min, size_max)
    profiles = [
        (3, video_ips,    [443],      "TCP", 800,  1400),
        (2, music_ips,    [443],      "TCP", 200,  600),
        (3, browsing_ips, [443, 80],  "TCP", 100,  500),
        (1, browsing_ips, [53],       "UDP", 60,   120),
        (1, ["10.0.0.1"], [22, 8080], "TCP", 60,   200),
    ]

    # Build weighted list
    weighted = []
    for profile in profiles:
        weight = profile[0]
        weighted.extend([profile] * weight)

    print("[Sniffer] Simulation started. Traffic will appear as video/music/browsing.")

    while sniffer_state["running"]:
        try:
            _, dst_pool, ports, proto, sz_min, sz_max = random.choice(weighted)
            dst_ip   = random.choice(dst_pool)
            dst_port = random.choice(ports)
            src_port = random.randint(49152, 65535)
            size     = random.randint(sz_min, sz_max)

            category = classifier.classify_packet(my_ip, dst_ip, src_port, dst_port)

            _save_and_broadcast({
                "src_ip":    my_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "protocol":  proto,
                "category":  category,
                "size":      size,
                "timestamp": datetime.datetime.now().isoformat(),
                "mode":      "simulation"
            })

            time.sleep(random.uniform(0.15, 0.4))

        except Exception as e:
            print(f"[Simulation] Error: {e}")
            time.sleep(1)


# ============================================================
# PART 5 — LIVE CAPTURE LOOP
# ============================================================

def _live_capture_loop():
    global capture_mode
    capture_mode = "live"
    while sniffer_state["running"]:
        try:
            kwargs = dict(prn=process_packet, store=False, timeout=1, count=0)
            if active_interface:
                kwargs["iface"] = active_interface
            scapy_sniff(**kwargs)
        except Exception as e:
            print(f"[Sniffer] Capture error: {e}")
            time.sleep(1)


def _test_live_capture() -> bool:
    """
    Sniffs for 2 seconds and checks if any non-Docker packets arrive.
    Returns True if real network traffic is visible.
    """
    test_packets = []
    try:
        kwargs = dict(
            prn=lambda p: test_packets.append(p),
            store=True, timeout=2, count=0
        )
        if active_interface:
            kwargs["iface"] = active_interface
        scapy_sniff(**kwargs)
    except Exception as e:
        print(f"[Sniffer] Live test failed: {e}")
        return False

    # Real packets = have IP layer AND not from Docker bridge (172.17.x.x)
    real = [
        p for p in test_packets
        if p.haslayer(IP) and not p[IP].src.startswith("172.17.")
                           and not p[IP].dst.startswith("172.17.")
    ]

    print(f"[Sniffer] Live test: {len(test_packets)} total packets, {len(real)} real IP packets")
    return len(real) > 0


# ============================================================
# PART 6 — PUBLIC API
# ============================================================

def start_sniffer():
    """
    Starts the sniffer. Automatically chooses live vs simulation.

    Sequence:
      1. Seed DNS table (ensures classification works from second 1)
      2. Detect best network interface
      3. Test if live capture sees real packets
      4. Start live loop OR simulation loop accordingly
    """
    global active_interface, capture_mode

    sniffer_state["running"] = True
    storage.clear_all()
    classifier.ip_category_table.clear()

    # Step 1: Seed DNS
    seed_common_services()

    # Step 2: Interface
    active_interface = get_best_interface()

    # Step 3: Test live capture
    print("[Sniffer] Testing whether live packet capture works...")
    live_ok = _test_live_capture()

    # Step 4: Start correct loop
    if live_ok:
        print("[Sniffer] SUCCESS: Live mode active. Capturing real packets.")
        target = _live_capture_loop
    else:
        print("[Sniffer] NOTICE: Switching to simulation mode.")
        print("[Sniffer] ---- To enable live capture: ----")
        print("[Sniffer]   Stop Docker. Run locally:")
        print("[Sniffer]   Windows: open PowerShell as Admin, then:")
        print("[Sniffer]   uvicorn main:app --reload --port 8000")
        target = _simulation_loop

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread


def stop_sniffer():
    global capture_mode
    sniffer_state["running"] = False
    capture_mode = "stopped"


# ============================================================
# PART 7 — SHARED HELPER
# ============================================================

def _save_and_broadcast(summary: dict):
    """Saves packet to storage and sends to WebSocket clients."""
    storage.add_packet(summary)
    if broadcast_callback:
        try:
            asyncio.run(broadcast_callback({"type": "packet", "data": summary}))
        except Exception:
            pass