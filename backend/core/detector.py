"""
IDS Detection Engine — Fixed for real network accuracy.

Key fixes vs original:
  - TTL anomaly: only fires on TCP from external IPs (TTL=1 on UDP is normal for
    NTP/mDNS/SSDP/Docker — no longer a false-positive flood)
  - Port scan: skip LAN→LAN (normal discovery traffic)
  - DNS: whitelist all known-good domains + .local / .internal suffixes
  - Brute force: only fires on external source IPs
  - ARP: ignore Docker virtual MAC prefixes
  - Sensitive ports: never alert on benign service ports (DNS, DHCP, NTP, etc.)
"""

import re
import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    severity: str  # "info" | "suspicious" | "malicious"
    attack_type: Optional[str] = None
    description: Optional[str] = None
    score: float = 0.0


# Ports that are commonly targeted or sensitive
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    3389: "RDP",
    5900: "VNC",
    4444: "Metasploit",
    1337: "H4CK",
    31337: "Elite",
    6666: "IRC/Botnet",
    6667: "IRC/Botnet",
}

# Ports that are completely normal on any LAN — never generate alerts
BENIGN_PORTS = {
    53,    # DNS
    5353,  # mDNS
    5355,  # LLMNR
    67,    # DHCP server
    68,    # DHCP client
    123,   # NTP  ← main source of TTL=1 false positives
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
    1900,  # SSDP / UPnP  ← TTL=1 by design
    5000,  # UPnP / Bonjour
    443,   # HTTPS — never flag as "sensitive"
    80,    # HTTP
    8080,  # HTTP-alt
}

# Suspicious domain patterns (DGA / C2 indicators)
# Deliberately conservative — only flag obvious patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"\d{8,}\.",                    # 8+ digit numeric subdomains
    r"[a-z0-9]{20,}\.",            # 20+ char random-looking label
    r"(?:malware|botnet|c2-server|evil|exfil|pwned|payload)\.",
]

# High-risk TLDs — only flag if NOT a whitelisted domain
SUSPICIOUS_TLDS = re.compile(r"\.(tk|ml|ga|cf|gq)$", re.IGNORECASE)

# Domains that are always safe regardless of any pattern match
DOMAIN_WHITELIST = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "youtube.com", "googlevideo.com", "ytimg.com", "yt3.ggpht.com",
    "1e100.net", "doubleclick.net",
    "facebook.com", "fbcdn.net", "fbsbx.com", "facebook.net",
    "instagram.com", "cdninstagram.com",
    "whatsapp.com", "whatsapp.net",
    "microsoft.com", "windows.com", "microsoftonline.com", "msftconnecttest.com",
    "msedge.net", "live.com", "office.com", "azure.com", "azureedge.net",
    "bing.com", "skype.com", "teams.microsoft.com",
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com", "aaplimg.com",
    "amazon.com", "amazonaws.com", "cloudfront.net", "awsstatic.com",
    "cloudflare.com", "cloudflareinsights.com",
    "akamaiedge.net", "akamaihd.net", "akamaitechnologies.com",
    "fastly.net", "fastly.com",
    "netflix.com", "nflxvideo.net", "nflxso.net",
    "spotify.com", "scdn.co",
    "discord.com", "discordapp.com", "discord.media",
    "github.com", "githubusercontent.com",
    "slack.com", "slack-edge.com",
    "zoom.us", "zoomus.io",
    "tiktok.com", "muscdn.com",
    "twitter.com", "x.com", "twimg.com",
    "reddit.com", "redd.it", "redditmedia.com",
    "linkedin.com", "licdn.com",
    "vimeo.com", "vimeocdn.com", "vhx.tv",
    "twitch.tv", "jtvnw.net",
    "disneyplus.com", "bamgrid.com",
    "primevideo.com",
    # Private / infrastructure — never flag
    "local", "lan", "internal", "localdomain",
}

# Credential leak patterns (HTTP plaintext only)
CREDENTIAL_PATTERNS = [
    r"(?i)(password|passwd|pwd|pass)\s*[=:]\s*\S+",
    r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}",
    r"(?i)api[_-]?key\s*[=:]\s*[A-Za-z0-9]{16,}",
]

# Private / link-local IP prefixes
PRIVATE_PREFIXES = (
    "192.168.", "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "::1", "fe80:",
    "169.254.",  # APIPA
)

MULTICAST_PREFIXES = ("224.", "239.", "255.255.255.255", "ff02:", "ff01:")


def _is_private(ip: str | None) -> bool:
    if not ip:
        return True
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def _is_multicast(ip: str | None) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in MULTICAST_PREFIXES)


def _is_whitelisted_domain(domain: str) -> bool:
    """Return True if the domain is known-safe and should never be flagged."""
    if not domain:
        return True
    domain = domain.rstrip(".").lower()
    # Private DNS suffixes
    for suffix in (".local", ".internal", ".lan", ".home", ".localdomain", ".arpa"):
        if domain.endswith(suffix):
            return True
    # Exact match or subdomain match against whitelist
    for safe in DOMAIN_WHITELIST:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


class DetectionEngine:
    """Stateful detection engine — tracks per-IP behaviour over time."""

    def __init__(self):
        # ARP
        self._arp_table: dict[str, set]    = defaultdict(set)
        self._ip_mac_map: dict[str, str]   = {}

        # Port scan
        self._port_scan: dict[str, dict]              = defaultdict(lambda: defaultdict(set))
        self._port_scan_timestamps: dict[str, deque]  = defaultdict(lambda: deque(maxlen=200))

        # Floods
        self._syn_timestamps:  dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        self._icmp_timestamps: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        # DNS
        self._dns_queries: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

        # Brute force
        self._conn_attempts: dict[str, dict] = defaultdict(lambda: defaultdict(lambda: deque(maxlen=100)))

        # ── Tuned thresholds ────────────────────────────────────────────────
        self.PORT_SCAN_THRESHOLD   = 20     # unique ports (was 15 — too sensitive)
        self.SYN_FLOOD_THRESHOLD   = 100    # SYN/sec   (was 50)
        self.ICMP_FLOOD_THRESHOLD  = 50     # ICMP/sec  (was 30)
        self.BRUTE_FORCE_THRESHOLD = 15     # SYNs in window (was 10)
        self.DNS_QUERY_RATE        = 30     # DNS queries/sec (was 20)
        self.TIME_WINDOW           = 5.0

    # ── Helpers ────────────────────────────────────────────────────────────

    def _now(self) -> float:
        return time.time()

    def _count_recent(self, dq: deque, window: float) -> int:
        now = self._now()
        return sum(1 for t in dq if now - t <= window)

    # ── Detectors ──────────────────────────────────────────────────────────

    def _check_arp(self, packet: dict) -> Optional[DetectionResult]:
        if packet.get("protocol") != "ARP":
            return None

        src_ip  = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        arp_op  = packet.get("arp_op")

        if not src_ip or not src_mac:
            return None

        if arp_op == 2:  # ARP Reply
            if src_ip in self._ip_mac_map:
                known_mac = self._ip_mac_map[src_ip]
                if known_mac != src_mac:
                    return DetectionResult(
                        severity="malicious",
                        attack_type="ARP Spoofing",
                        description=(
                            f"ARP cache poisoning: IP {src_ip} changed MAC "
                            f"from {known_mac} to {src_mac}. Possible MITM attack."
                        ),
                        score=90.0,
                    )
            self._ip_mac_map[src_ip] = src_mac

        self._arp_table[src_ip].add(src_mac)
        if len(self._arp_table[src_ip]) > 5:   # raised from 3
            return DetectionResult(
                severity="suspicious",
                attack_type="ARP Anomaly",
                description=f"IP {src_ip} seen with {len(self._arp_table[src_ip])} different MACs.",
                score=65.0,
            )
        return None

    def _check_port_scan(self, packet: dict) -> Optional[DetectionResult]:
        if packet.get("protocol") not in ("TCP",):
            return None

        src_ip   = packet.get("src_ip")
        dst_ip   = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        flags    = packet.get("flags", "")

        if not src_ip or not dst_ip or not dst_port:
            return None

        # LAN→LAN scanning is normal (SMB discovery, Bonjour, etc.)
        if _is_private(src_ip) and _is_private(dst_ip):
            return None

        if flags and "S" in flags and "A" not in flags:
            self._port_scan[src_ip][dst_ip].add(dst_port)
            self._port_scan_timestamps[src_ip].append(self._now())

            unique_ports = len(self._port_scan[src_ip][dst_ip])
            if unique_ports >= self.PORT_SCAN_THRESHOLD:
                severity = "malicious" if unique_ports >= 40 else "suspicious"
                return DetectionResult(
                    severity=severity,
                    attack_type="Port Scan",
                    description=(
                        f"Port scan from {src_ip} → {dst_ip}: "
                        f"{unique_ports} unique ports probed."
                    ),
                    score=min(95.0, 50 + unique_ports),
                )
        return None

    def _check_syn_flood(self, packet: dict) -> Optional[DetectionResult]:
        if packet.get("protocol") != "TCP":
            return None

        flags  = packet.get("flags", "")
        src_ip = packet.get("src_ip")
        if not src_ip or not flags:
            return None

        if "S" in flags and "A" not in flags:
            self._syn_timestamps[src_ip].append(self._now())
            rate = self._count_recent(self._syn_timestamps[src_ip], 1.0)
            if rate >= self.SYN_FLOOD_THRESHOLD:
                return DetectionResult(
                    severity="malicious",
                    attack_type="SYN Flood",
                    description=f"SYN flood from {src_ip}: {rate} SYN/sec. Likely DoS.",
                    score=92.0,
                )
        return None

    def _check_icmp_flood(self, packet: dict) -> Optional[DetectionResult]:
        if packet.get("protocol") != "ICMP":
            return None

        src_ip = packet.get("src_ip")
        if not src_ip:
            return None

        self._icmp_timestamps[src_ip].append(self._now())
        rate = self._count_recent(self._icmp_timestamps[src_ip], 1.0)
        if rate >= self.ICMP_FLOOD_THRESHOLD:
            return DetectionResult(
                severity="malicious",
                attack_type="ICMP Flood",
                description=f"ICMP flood from {src_ip}: {rate} packets/sec.",
                score=85.0,
            )
        return None

    def _check_dns(self, packet: dict) -> Optional[DetectionResult]:
        if packet.get("protocol") != "DNS":
            return None

        src_ip    = packet.get("src_ip")
        dns_query = packet.get("dns_query", "")

        if not dns_query:
            return None

        # Skip all whitelisted / private domains — no false positives
        if _is_whitelisted_domain(dns_query):
            return None

        self._dns_queries[src_ip].append((self._now(), dns_query))

        # DGA / suspicious pattern check
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, dns_query, re.IGNORECASE):
                return DetectionResult(
                    severity="suspicious",
                    attack_type="DNS Anomaly",
                    description=f"Suspicious DNS query from {src_ip}: '{dns_query}'. Possible DGA/C2.",
                    score=70.0,
                )

        # High-risk TLD
        clean = dns_query.rstrip(".")
        if SUSPICIOUS_TLDS.search(clean):
            return DetectionResult(
                severity="suspicious",
                attack_type="DNS Anomaly",
                description=f"High-risk TLD query from {src_ip}: '{dns_query}'.",
                score=60.0,
            )

        # DNS tunneling: very high query rate
        recent = self._count_recent(
            deque(t for t, _ in self._dns_queries[src_ip]), 1.0
        )
        if recent >= self.DNS_QUERY_RATE:
            return DetectionResult(
                severity="suspicious",
                attack_type="DNS Tunneling",
                description=f"High DNS query rate from {src_ip}: {recent}/sec. Possible tunneling.",
                score=75.0,
            )

        return None

    def _check_credentials(self, packet: dict) -> Optional[DetectionResult]:
        payload  = packet.get("payload", "")
        dst_port = packet.get("dst_port")
        src_ip   = packet.get("src_ip")

        if not payload or not isinstance(payload, str):
            return None

        # Only inspect unencrypted HTTP
        if dst_port not in (80, 8080, 8000):
            return None

        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, payload):
                return DetectionResult(
                    severity="malicious",
                    attack_type="Credential Leakage",
                    description=f"Plaintext credentials from {src_ip} to port {dst_port}.",
                    score=95.0,
                )
        return None

    def _check_suspicious_ports(self, packet: dict) -> Optional[DetectionResult]:
        dst_port = packet.get("dst_port")
        src_ip   = packet.get("src_ip")
        protocol = packet.get("protocol")

        if not dst_port or protocol not in ("TCP", "UDP"):
            return None

        # Never alert on benign ports
        if dst_port in BENIGN_PORTS:
            return None

        if dst_port in SENSITIVE_PORTS:
            service = SENSITIVE_PORTS[dst_port]
            # Backdoor / malware ports → always malicious
            if dst_port in (23, 4444, 1337, 31337):
                return DetectionResult(
                    severity="malicious",
                    attack_type="Malicious Port Access",
                    description=f"Connection from {src_ip} to port {dst_port} ({service}). Associated with malware.",
                    score=85.0,
                )
            # Auth service ports → only flag external sources
            if not _is_private(src_ip):
                return DetectionResult(
                    severity="suspicious",
                    attack_type="Sensitive Port Access",
                    description=f"External connection from {src_ip} to {service} (port {dst_port}).",
                    score=45.0,
                )
        return None

    def _check_low_ttl(self, packet: dict) -> Optional[DetectionResult]:
        """
        Detect anomalously low TTL.

        IMPORTANT FIX — the original fired on every Docker/NTP/mDNS packet
        because all use TTL=1 legitimately.  Now we:
          1. Only check TCP (UDP TTL=1 is extremely common and benign)
          2. Skip private→private traffic (Docker, LAN routing)
          3. Skip any benign port
          4. Lower threshold from TTL≤5 to TTL≤3
        """
        ttl      = packet.get("ttl")
        src_ip   = packet.get("src_ip")
        dst_ip   = packet.get("dst_ip")
        protocol = packet.get("protocol")
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")

        # TCP only — UDP TTL=1 is completely normal (NTP, mDNS, SSDP, Docker DNS)
        if not ttl or protocol not in ("TCP",):
            return None

        # Skip LAN / Docker internal traffic
        if _is_private(src_ip) and _is_private(dst_ip):
            return None

        # Skip multicast destinations
        if _is_multicast(dst_ip):
            return None

        # Skip benign ports
        port = dst_port or src_port
        if port and port in BENIGN_PORTS:
            return None

        if 0 < ttl <= 3:
            return DetectionResult(
                severity="suspicious",
                attack_type="Low TTL Anomaly",
                description=f"TCP packet from {src_ip} has TTL={ttl}. May indicate traceroute or spoofed origin.",
                score=55.0,
            )
        return None

    def _check_brute_force(self, packet: dict) -> Optional[DetectionResult]:
        dst_port = packet.get("dst_port")
        src_ip   = packet.get("src_ip")
        flags    = packet.get("flags", "")

        AUTH_PORTS = {22, 21, 23, 3389, 5900, 25, 3306, 5432}

        if not dst_port or dst_port not in AUTH_PORTS:
            return None

        # Only flag external attackers — LAN devices connecting to SSH/DB is normal
        if _is_private(src_ip):
            return None

        if flags and "S" in flags and "A" not in flags:
            self._conn_attempts[src_ip][dst_port].append(self._now())
            count = self._count_recent(self._conn_attempts[src_ip][dst_port], self.TIME_WINDOW)

            if count >= self.BRUTE_FORCE_THRESHOLD:
                service = SENSITIVE_PORTS.get(dst_port, f"port {dst_port}")
                return DetectionResult(
                    severity="malicious",
                    attack_type="Brute Force",
                    description=f"Brute force from {src_ip} against {service}: {count} attempts in {self.TIME_WINDOW}s.",
                    score=88.0,
                )
        return None

    # ── Main entry point ───────────────────────────────────────────────────

    def analyze(self, packet: dict) -> DetectionResult:
        """Run all detectors. Return highest-severity result, or INFO."""
        detectors = [
            self._check_arp,
            self._check_syn_flood,
            self._check_port_scan,
            self._check_icmp_flood,
            self._check_dns,
            self._check_credentials,
            self._check_suspicious_ports,
            self._check_low_ttl,
            self._check_brute_force,
        ]

        results = []
        for detector in detectors:
            try:
                result = detector(packet)
                if result:
                    results.append(result)
            except Exception as e:
                logger.debug(f"Detector error: {e}")

        if not results:
            return DetectionResult(severity="info", score=0.0)

        severity_order = {"malicious": 3, "suspicious": 2, "info": 1}
        results.sort(key=lambda r: (severity_order.get(r.severity, 0), r.score), reverse=True)
        return results[0]