# ============================================================
# detector.py — Attack & Threat Detector
# ============================================================
# Checks each packet for known attack patterns:
#   1. ARP Spoofing  — someone lying about their MAC address
#   2. Credential Leaks — passwords sent in plain HTTP text
# ============================================================

# -----------------------------------------------------------
# What is ARP Spoofing?
# -----------------------------------------------------------
# ARP = Address Resolution Protocol
# It maps IP addresses → MAC addresses on your local network.
# Example: "Who has IP 192.168.1.1?" → "I do, my MAC is AA:BB:CC"
#
# In ARP Spoofing, an attacker sends FAKE ARP replies saying:
# "I am the router (192.168.1.1)" — but with their own MAC.
# Your computer then sends ALL traffic to the attacker. 😱
#
# HOW WE DETECT IT:
# We keep a table: { IP → MAC }
# If an IP suddenly has a DIFFERENT MAC than before → suspicious!
# -----------------------------------------------------------

# -----------------------------------------------------------
# What are Credential Leaks?
# -----------------------------------------------------------
# If a website uses plain HTTP (not HTTPS), your username and
# password travel as raw text in the network packet.
# We scan HTTP packet payloads for keywords like "password=".
# -----------------------------------------------------------

import storage   # we save alerts here

# Tracks: IP address → MAC address (for ARP table)
arp_table = {}

# Keywords that might indicate credentials in plain text
CREDENTIAL_KEYWORDS = [
    b"password=",
    b"passwd=",
    b"pass=",
    b"pwd=",
    b"login=",
    b"username=",
    b"user=",
    b"email=",
    b"Authorization:",
]


# -----------------------------------------------------------
# ARP Spoofing Detector
# -----------------------------------------------------------
def check_arp_spoofing(packet) -> bool:
    """
    Receives a Scapy packet.
    Returns True if ARP spoofing is detected, False otherwise.

    Scapy ARP packet fields:
      packet[ARP].op   → 2 = "is-at" (ARP reply, this is what attackers send)
      packet[ARP].psrc → sender's IP address
      packet[ARP].hwsrc → sender's MAC address
    """
    from scapy.layers.l2 import ARP   # import here to avoid errors if scapy missing

    # Only check ARP reply packets (op == 2 means "is-at" / reply)
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        sender_ip  = packet[ARP].psrc    # IP claiming to be this address
        sender_mac = packet[ARP].hwsrc   # MAC of the sender

        # Have we seen this IP before?
        if sender_ip in arp_table:
            known_mac = arp_table[sender_ip]

            # Is the MAC DIFFERENT from what we recorded?
            if known_mac != sender_mac:
                # 🚨 Possible ARP Spoofing!
                alert = {
                    "type": "ARP Spoofing",
                    "detail": (
                        f"IP {sender_ip} previously had MAC {known_mac} "
                        f"but now claims MAC {sender_mac}"
                    ),
                    "severity": "HIGH",
                    "timestamp": _now()
                }
                storage.add_alert(alert)
                return True
        else:
            # First time we see this IP — record it
            arp_table[sender_ip] = sender_mac

    return False


# -----------------------------------------------------------
# Credential Leak Detector
# -----------------------------------------------------------
def check_credential_leak(packet) -> bool:
    """
    Checks if an HTTP packet payload contains credential keywords.
    Returns True if a potential credential leak is found.

    We only check port 80 (plain HTTP) — HTTPS is encrypted so
    we can't read it, and it's safe anyway.
    """
    from scapy.layers.inet import TCP, IP

    # Only check TCP packets (HTTP runs on TCP)
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False

    tcp_layer = packet[TCP]

    # Only check packets going TO port 80 (HTTP request)
    if tcp_layer.dport != 80:
        return False

    # Try to get the raw payload (the actual HTTP data)
    try:
        payload = bytes(tcp_layer.payload)
    except Exception:
        return False

    if not payload:
        return False

    # Search for credential keywords (case-insensitive)
    payload_lower = payload.lower()
    for keyword in CREDENTIAL_KEYWORDS:
        if keyword.lower() in payload_lower:
            src_ip = packet[IP].src
            alert = {
                "type": "Credential Leak",
                "detail": (
                    f"Possible credential in plain HTTP from {src_ip}. "
                    f"Keyword detected: {keyword.decode()}"
                ),
                "severity": "CRITICAL",
                "timestamp": _now()
            }
            storage.add_alert(alert)
            return True

    return False


# -----------------------------------------------------------
# Master: run all detectors on one packet
# -----------------------------------------------------------
def run_detectors(packet):
    """
    Runs every detector on a packet.
    Call this once per captured packet.
    """
    check_arp_spoofing(packet)
    check_credential_leak(packet)


# -----------------------------------------------------------
# Utility
# -----------------------------------------------------------
def _now() -> str:
    """Returns current time as an ISO string."""
    import datetime
    return datetime.datetime.now().isoformat()
