"""
IDS Engine — orchestrates capture, detection, DB persistence, and WebSocket broadcasting.
"""

import asyncio
import logging
import socket
import time
from datetime import datetime
from typing import Optional, Callable
from collections import defaultdict, deque

from .capture import PacketCapture
from .detector import DetectionEngine, DetectionResult

logger = logging.getLogger(__name__)


class IDSEngine:
    def __init__(self, interface: Optional[str] = None):
        self.capture  = PacketCapture(interface=interface)
        self.detector = DetectionEngine()
        self.is_running = False

        # Reverse DNS cache: ip -> hostname (None = failed, missing = not yet tried)
        self._dns_cache:   dict[str, str | None] = {}
        self._dns_pending: set[str]              = set()

        # Stats
        self.stats = {
            "total_packets":    0,
            "info_count":       0,
            "suspicious_count": 0,
            "malicious_count":  0,
            "start_time":       None,
            "protocols":        defaultdict(int),
            "top_src_ips":      defaultdict(int),
            "alerts_today":     0,
        }

        # Rolling window for bandwidth calculation (2-second window)
        self._bandwidth_window: deque = deque(maxlen=2000)

        # Callbacks
        self._packet_callbacks: list[Callable] = []
        self._alert_callbacks:  list[Callable] = []

        # Rate limiting for alerts (deduplicate same alert type+IP within 10s)
        self._recent_alerts: dict[str, float] = {}
        self.ALERT_COOLDOWN = 10.0

    def _schedule_dns(self, ip: str):
        """Fire-and-forget background reverse DNS lookup."""
        if not ip or ip in self._dns_cache or ip in self._dns_pending:
            return
        self._dns_pending.add(ip)
        asyncio.create_task(self._resolve_ip(ip))

    async def _resolve_ip(self, ip: str):
        """Resolve an IP to hostname with a 0.8s timeout (reduced from 1.5s)."""
        try:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=0.8,
            )
            self._dns_cache[ip] = result[0]
        except Exception:
            self._dns_cache[ip] = None
        finally:
            self._dns_pending.discard(ip)

    def _get_hostname(self, ip: str | None) -> str | None:
        if not ip:
            return None
        if ip not in self._dns_cache:
            self._schedule_dns(ip)
        return self._dns_cache.get(ip)

    def on_packet(self, callback: Callable):
        self._packet_callbacks.append(callback)

    def on_alert(self, callback: Callable):
        self._alert_callbacks.append(callback)

    async def _notify_packet(self, event: dict):
        for cb in self._packet_callbacks:
            try:
                await cb(event)
            except Exception as e:
                logger.debug(f"Packet callback error: {e}")

    async def _notify_alert(self, alert: dict):
        for cb in self._alert_callbacks:
            try:
                await cb(alert)
            except Exception as e:
                logger.debug(f"Alert callback error: {e}")

    def _should_alert(self, attack_type: str, src_ip: str) -> bool:
        """Rate-limit duplicate alerts."""
        key  = f"{attack_type}:{src_ip}"
        now  = time.time()
        last = self._recent_alerts.get(key, 0)
        if now - last >= self.ALERT_COOLDOWN:
            self._recent_alerts[key] = now
            return True
        return False

    def _update_stats(self, packet: dict, result: DetectionResult):
        self.stats["total_packets"] += 1

        severity = result.severity
        self.stats[f"{severity}_count"] += 1

        proto = packet.get("protocol", "UNKNOWN")
        self.stats["protocols"][proto] += 1

        src_ip = packet.get("src_ip")
        if src_ip:
            self.stats["top_src_ips"][src_ip] += 1

        self._bandwidth_window.append((time.time(), packet.get("packet_size", 0)))

    def get_bandwidth_bps(self) -> float:
        now    = time.time()
        recent = [(t, s) for t, s in self._bandwidth_window if now - t <= 2.0]
        if len(recent) < 2:
            return 0.0
        total_bytes = sum(s for _, s in recent)
        return total_bytes / 2.0

    def get_stats_snapshot(self) -> dict:
        top_ips = sorted(
            self.stats["top_src_ips"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        proto_dist = dict(sorted(
            self.stats["protocols"].items(),
            key=lambda x: x[1],
            reverse=True,
        )[:8])

        uptime = 0
        if self.stats["start_time"]:
            uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            "total_packets":         self.stats["total_packets"],
            "info_count":            self.stats["info_count"],
            "suspicious_count":      self.stats["suspicious_count"],
            "malicious_count":       self.stats["malicious_count"],
            "bandwidth_bps":         self.get_bandwidth_bps(),
            "protocol_distribution": proto_dist,
            "top_src_ips":           [{"ip": ip, "count": c} for ip, c in top_ips],
            "uptime_seconds":        uptime,
            "is_running":            self.is_running,
        }

    async def process_loop(self):
        """Main processing loop: consume packets, detect, notify."""
        while self.is_running:
            packet = await self.capture.get_packet()

            if packet is None:
                await asyncio.sleep(0.005)  # 5ms sleep when idle (was 10ms)
                continue

            result = self.detector.analyze(packet)
            self._update_stats(packet, result)

            event = {
                **packet,
                "severity":     result.severity,
                "attack_type":  result.attack_type,
                "description":  result.description,
                "score":        result.score,
                "src_hostname": packet.get("src_hostname") or self._get_hostname(packet.get("src_ip")),
                "dst_hostname": packet.get("dst_hostname") or self._get_hostname(packet.get("dst_ip")),
            }

            await self._notify_packet(event)

            if result.severity in ("suspicious", "malicious"):
                src_ip      = packet.get("src_ip", "unknown")
                attack_type = result.attack_type or "Unknown"

                if self._should_alert(attack_type, src_ip):
                    self.stats["alerts_today"] += 1
                    alert = {
                        "id":          self.stats["alerts_today"],
                        "timestamp":   packet["timestamp"],
                        "alert_type":  attack_type,
                        "severity":    result.severity,
                        "src_ip":      src_ip,
                        "dst_ip":      packet.get("dst_ip"),
                        "description": result.description,
                        "score":       result.score,
                    }
                    await self._notify_alert(alert)

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.stats["start_time"] = datetime.utcnow()
        await self.capture.start()
        asyncio.create_task(self.process_loop())
        logger.info("IDS Engine started — live capture mode")

    async def stop(self):
        self.is_running = False
        await self.capture.stop()
        logger.info("IDS Engine stopped")