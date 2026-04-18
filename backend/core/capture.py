"""
Packet Capture Engine — Real-time live capture using Scapy.
Captures ALL packets on the wire in promiscuous mode (like Wireshark).
Requires root/admin privileges: run with  sudo python main.py  on Linux.
"""

import asyncio
import logging
import threading
import queue
import socket
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# TLS SNI extractor (no external deps)
# ──────────────────────────────────────────────

def _extract_tls_sni(data: bytes) -> str | None:
    """
    Parse a TLS ClientHello record and return the SNI hostname, or None.
    Pure byte inspection — no extra dependencies required.
    """
    try:
        if len(data) < 5 or data[0] != 0x16:          # 0x16 = Handshake
            return None
        record_len = int.from_bytes(data[3:5], "big")
        if len(data) < 5 + record_len:
            return None
        hs = data[5:]
        if not hs or hs[0] != 0x01:                   # 0x01 = ClientHello
            return None
        # Skip: type(1) + length(3) + version(2) + random(32) = 38
        pos = 38
        if len(hs) < pos + 1:
            return None
        sid_len = hs[pos]; pos += 1 + sid_len
        if len(hs) < pos + 2:
            return None
        cs_len = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2 + cs_len
        if len(hs) < pos + 1:
            return None
        cm_len = hs[pos]; pos += 1 + cm_len
        if len(hs) < pos + 2:
            return None
        ext_total = int.from_bytes(hs[pos:pos + 2], "big"); pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type = int.from_bytes(hs[pos:pos + 2], "big")
            ext_len  = int.from_bytes(hs[pos + 2:pos + 4], "big")
            pos += 4
            if ext_type == 0x0000 and ext_len > 5:     # SNI extension
                name_len = int.from_bytes(hs[pos + 3:pos + 5], "big")
                sni = hs[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
                return sni if sni else None
            pos += ext_len
    except Exception:
        pass
    return None


# ──────────────────────────────────────────────
# Scapy import — hard requirement
# ──────────────────────────────────────────────

try:
    from scapy.all import (
        sniff, conf,
        IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest,
        ARP, DNS, DNSQR, Raw, Ether,
        get_if_list, IFACES,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.error(
        "Scapy is not installed. Install it with:  pip install scapy\n"
        "Then re-run with root: sudo python main.py"
    )


# ──────────────────────────────────────────────
# Interface helpers
# ──────────────────────────────────────────────

_SKIP_TERMS = [
    "loopback", "vmware", "vmnet", "virtual", "pseudo",
    "wan miniport", "wi-fi direct", "bluetooth", "169.254",
]


def get_available_interfaces() -> list[dict]:
    """Return a list of all network interfaces visible to Scapy."""
    if not SCAPY_AVAILABLE:
        return []
    result = []
    try:
        for iface in IFACES.values():
            result.append({
                "name":        iface.name,
                "description": getattr(iface, "description", iface.name) or iface.name,
                "ip":          getattr(iface, "ip",          "") or "",
                "guid":        getattr(iface, "guid",        "") or "",
            })
    except Exception:
        pass
    return result


def auto_detect_interface() -> str | None:
    """
    Pick the best active physical interface automatically —
    same heuristic as Wireshark's default interface selection.
    Returns the Scapy interface name, or None to let Scapy use its own default.
    """
    if not SCAPY_AVAILABLE:
        return None
    try:
        candidates = []
        for iface in IFACES.values():
            name     = iface.name or ""
            desc     = getattr(iface, "description", "") or ""
            ip       = getattr(iface, "ip", "")          or ""
            combined = (name + " " + desc + " " + ip).lower()

            if any(t in combined for t in _SKIP_TERMS):
                continue
            if not ip or ip.startswith("127."):
                continue

            score = 0
            if any(w in combined for w in ("wi-fi", "wifi", "wireless", "wlan")):
                score += 10
            elif any(w in combined for w in ("ethernet", "eth", "en0", "en1")):
                score += 8
            candidates.append((score, name))

        if candidates:
            candidates.sort(key=lambda x: -x[0])
            logger.info(f"[capture] Auto-selected interface: {candidates[0][1]!r}")
            return candidates[0][1]
    except Exception:
        pass

    try:
        return conf.iface
    except Exception:
        return None


# ──────────────────────────────────────────────
# Main capture class
# ──────────────────────────────────────────────

class PacketCapture:
    """
    Real-time packet capture using Scapy in promiscuous mode.

    • Captures ALL IP packets on your system's active network interface.
    • Uses a BPF kernel filter ("ip or ip6") to drop non-IP noise at the
      kernel level before Python processes it — significant CPU saving.
    • Extracts TLS SNI for HTTPS streams.
    • Decodes HTTP payloads from plain-text TCP streams.
    • Thread-safe: Scapy runs in a daemon thread; packets are queued for
      async consumers via a 50,000-slot queue.

    REQUIRES: root/sudo on Linux.  Run as:  sudo python main.py
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
        bpf_filter: str = "ip or ip6",
        promisc: bool = True,
        queue_maxsize: int = 50_000,
    ):
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for live capture. "
                "Install it: pip install scapy"
            )

        self.interface       = interface or auto_detect_interface()
        self.packet_callback = packet_callback
        self.bpf_filter      = bpf_filter
        self.promisc         = promisc
        self._queue_maxsize  = queue_maxsize

        self.is_running      = False
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_queue:   queue.Queue = queue.Queue(maxsize=queue_maxsize)
        self.captured_count   = 0

        logger.info(
            f"PacketCapture ready  interface={self.interface!r}  "
            f"promisc={promisc}  filter={bpf_filter!r}"
        )

    # ── Packet parser ──────────────────────────────────────────────────────

    def _parse_packet(self, pkt) -> Optional[dict]:
        """Convert a raw Scapy packet into a normalised dict."""
        try:
            ts  = datetime.now(timezone.utc).isoformat()
            out = {
                "timestamp":    ts,
                "protocol":     "UNKNOWN",
                "src_ip":       None,
                "dst_ip":       None,
                "src_port":     None,
                "dst_port":     None,
                "packet_size":  len(pkt),
                "flags":        None,
                "ttl":          None,
                "raw_summary":  pkt.summary(),
                "payload":      None,
                "arp_op":       None,
                "dns_query":    None,
                "tls_sni":      None,
                "src_hostname": None,
                "dst_hostname": None,
                "src_mac":      None,
                "dst_mac":      None,
                "icmp_type":    None,
            }

            # ── Ethernet MACs ──────────────────────────────────────────────
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                out["src_mac"] = eth.src
                out["dst_mac"] = eth.dst

            # ── ARP ────────────────────────────────────────────────────────
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                out["protocol"] = "ARP"
                out["src_ip"]   = arp.psrc
                out["dst_ip"]   = arp.pdst
                out["arp_op"]   = arp.op
                out["src_mac"]  = arp.hwsrc
                out["dst_mac"]  = arp.hwdst
                return out

            # ── IPv4 ───────────────────────────────────────────────────────
            if pkt.haslayer(IP):
                ip = pkt[IP]
                out["src_ip"] = ip.src
                out["dst_ip"] = ip.dst
                out["ttl"]    = ip.ttl
                self._parse_transport(pkt, out)
                return out

            # ── IPv6 ───────────────────────────────────────────────────────
            if pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                out["src_ip"]   = ip6.src
                out["dst_ip"]   = ip6.dst
                out["protocol"] = "IPv6"
                self._parse_transport(pkt, out)
                return out

            return out

        except Exception as exc:
            logger.debug(f"Packet parse error: {exc}")
            return None

    def _parse_transport(self, pkt, out: dict):
        """Fill transport-layer fields into the output dict in-place."""

        # ── DNS (check before UDP so DNS over UDP is labelled DNS) ─────────
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            out["protocol"] = "DNS"
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                out["src_port"] = udp.sport
                out["dst_port"] = udp.dport
            if dns.qdcount and dns.qd:
                try:
                    raw = dns.qd.qname
                    name = raw.decode("utf-8", errors="ignore") if isinstance(raw, bytes) else str(raw)
                    out["dns_query"] = name.rstrip(".")
                except Exception:
                    pass
            return

        # ── TCP ────────────────────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            out["protocol"] = "TCP"
            out["src_port"] = tcp.sport
            out["dst_port"] = tcp.dport
            out["flags"]    = str(tcp.flags)

            port = tcp.dport or tcp.sport
            service_map = {
                80: "HTTP", 8080: "HTTP", 8000: "HTTP", 8888: "HTTP",
                443: "HTTPS", 8443: "HTTPS",
                22: "SSH", 21: "FTP", 25: "SMTP", 587: "SMTP",
                110: "POP3", 143: "IMAP", 993: "IMAP", 995: "POP3",
                3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                3389: "RDP", 5900: "VNC",
                53: "DNS",
            }
            if port in service_map:
                out["protocol"] = service_map[port]

            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw])

                try:
                    text = raw_bytes.decode("utf-8", errors="replace")
                    if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                        out["protocol"] = "HTTP"
                        out["payload"]  = text[:800]
                    elif text.startswith("HTTP/"):
                        out["protocol"] = "HTTP"
                        out["payload"]  = text[:400]
                    else:
                        out["payload"]  = text[:400]
                except Exception:
                    pass

                if port in (443, 8443):
                    sni = _extract_tls_sni(raw_bytes)
                    if sni:
                        out["tls_sni"]      = sni
                        out["dst_hostname"] = sni

            return

        # ── UDP ────────────────────────────────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            out["protocol"] = "UDP"
            out["src_port"] = udp.sport
            out["dst_port"] = udp.dport
            return

        # ── ICMP ───────────────────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            out["protocol"]  = "ICMP"
            out["icmp_type"] = pkt[ICMP].type
            return

        if pkt.haslayer(ICMPv6EchoRequest):
            out["protocol"] = "ICMPv6"
            return

    # ── Scapy capture thread ───────────────────────────────────────────────

    def _scapy_callback(self, pkt):
        """Called by Scapy for every captured packet (runs in capture thread)."""
        parsed = self._parse_packet(pkt)
        if parsed:
            self.captured_count += 1
            try:
                self._packet_queue.put_nowait(parsed)
            except queue.Full:
                # Drop oldest packet to make room — keep capture running
                try:
                    self._packet_queue.get_nowait()
                    self._packet_queue.put_nowait(parsed)
                except Exception:
                    pass

    def _capture_thread_func(self):
        """Run Scapy sniff() in a dedicated daemon thread."""
        logger.info(
            f"[capture] Starting LIVE capture  iface={self.interface!r}  "
            f"promisc={self.promisc}  filter={self.bpf_filter!r}"
        )

        kwargs: dict = {
            "prn":     self._scapy_callback,
            "store":   False,
            "promisc": self.promisc,
        }
        if self.interface:
            kwargs["iface"] = self.interface
        if self.bpf_filter:
            kwargs["filter"] = self.bpf_filter

        try:
            sniff(**kwargs)
        except PermissionError:
            logger.error(
                "\n"
                "══════════════════════════════════════════════════\n"
                "  PERMISSION DENIED — raw socket requires root.\n"
                "  Re-run the backend as:\n"
                "    sudo python main.py\n"
                "  or:  sudo uvicorn main:app --host 0.0.0.0 --port 8000\n"
                "══════════════════════════════════════════════════\n"
            )
        except OSError as exc:
            logger.error(f"[capture] OSError: {exc} — check interface name: {self.interface!r}")
        except Exception as exc:
            logger.error(f"[capture] Unexpected error: {exc}")

        logger.info("[capture] Thread exiting")

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def start(self):
        """Start live capture on the real network interface."""
        if self.is_running:
            return
        self.is_running = True
        self._capture_thread = threading.Thread(
            target=self._capture_thread_func,
            name="scapy-capture",
            daemon=True,
        )
        self._capture_thread.start()
        logger.info(f"[capture] LIVE capture started on {self.interface!r}")

    async def stop(self):
        """Stop packet capture gracefully."""
        self.is_running = False
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=3)
        logger.info("[capture] Stopped")

    async def get_packet(self) -> Optional[dict]:
        """Non-blocking retrieval of the next packet from the queue."""
        try:
            return self._packet_queue.get_nowait()
        except queue.Empty:
            return None

    @property
    def mode(self) -> str:
        return "live"