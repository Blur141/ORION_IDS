"""
FastAPI Backend for Real-Time IDS
Provides:
- REST API for events, alerts, stats
- WebSocket endpoint for live streaming
- DB persistence (batched writes for performance)
- Start/Stop/Reset controls
"""

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func, and_

from db.database import init_db, get_db, NetworkEvent, Alert
from core.engine import IDSEngine
from core.capture import auto_detect_interface

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="Real-Time IDS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global IDS engine instance
best_iface = auto_detect_interface()
logger.info(f"Auto-detected interface: {best_iface}")
ids_engine = IDSEngine(interface=best_iface)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WS client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        logger.info(f"WS client disconnected. Total: {len(self.active)}")

    async def broadcast(self, message: dict):
        if not self.active:
            return
        payload = json.dumps(message, default=str)
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# In-memory recent event buffer for WS (last 200 packets, last 50 alerts)
recent_packets: list[dict] = []
recent_alerts: list[dict] = []
MAX_BUFFER = 200
MAX_ALERTS = 50

# ── Batched DB write buffers ───────────────────────────────────────────────────
_event_batch:  list[dict] = []
_alert_batch:  list[dict] = []
BATCH_SIZE = 50  # flush every N items


async def _flush_event_batch():
    """Write buffered events to DB in a single transaction."""
    global _event_batch
    if not _event_batch:
        return
    batch = _event_batch[:BATCH_SIZE]
    _event_batch = _event_batch[BATCH_SIZE:]
    try:
        from db.database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            for event in batch:
                ne = NetworkEvent(
                    timestamp=datetime.fromisoformat(event["timestamp"]) if isinstance(event["timestamp"], str) else event["timestamp"],
                    src_ip=event.get("src_ip"),
                    dst_ip=event.get("dst_ip"),
                    src_port=event.get("src_port"),
                    dst_port=event.get("dst_port"),
                    protocol=event.get("protocol", "UNKNOWN"),
                    packet_size=event.get("packet_size", 0),
                    severity=event.get("severity", "info"),
                    attack_type=event.get("attack_type"),
                    description=event.get("description"),
                    raw_summary=event.get("raw_summary"),
                    flags=event.get("flags"),
                    ttl=event.get("ttl"),
                )
                db.add(ne)
            await db.commit()
    except Exception as e:
        logger.debug(f"DB batch event write error: {e}")


async def _flush_alert_batch():
    """Write buffered alerts to DB in a single transaction."""
    global _alert_batch
    if not _alert_batch:
        return
    batch = _alert_batch[:]
    _alert_batch = []
    try:
        from db.database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            for alert in batch:
                a = Alert(
                    timestamp=datetime.fromisoformat(alert["timestamp"]) if isinstance(alert["timestamp"], str) else alert["timestamp"],
                    alert_type=alert.get("alert_type", "Unknown"),
                    severity=alert.get("severity", "suspicious"),
                    src_ip=alert.get("src_ip", ""),
                    dst_ip=alert.get("dst_ip"),
                    description=alert.get("description", ""),
                )
                db.add(a)
            await db.commit()
    except Exception as e:
        logger.debug(f"DB batch alert write error: {e}")


async def on_packet(event: dict):
    """Called for every processed packet."""
    global recent_packets, _event_batch
    recent_packets.append(event)
    if len(recent_packets) > MAX_BUFFER:
        recent_packets = recent_packets[-MAX_BUFFER:]

    await manager.broadcast({"type": "packet", "data": event})

    # Accumulate into batch; flush when full
    _event_batch.append(event)
    if len(_event_batch) >= BATCH_SIZE:
        asyncio.create_task(_flush_event_batch())


async def on_alert(alert: dict):
    """Called for each new alert."""
    global recent_alerts, _alert_batch
    recent_alerts.append(alert)
    if len(recent_alerts) > MAX_ALERTS:
        recent_alerts = recent_alerts[-MAX_ALERTS:]

    await manager.broadcast({"type": "alert", "data": alert})

    _alert_batch.append(alert)
    asyncio.create_task(_flush_alert_batch())


async def _periodic_db_flush():
    """Flush remaining buffered events every 5 seconds regardless of batch size."""
    while True:
        await asyncio.sleep(5)
        if _event_batch:
            asyncio.create_task(_flush_event_batch())
        if _alert_batch:
            asyncio.create_task(_flush_alert_batch())


async def stats_broadcaster():
    """Broadcast stats snapshot every 2 seconds."""
    while True:
        await asyncio.sleep(2)
        if manager.active:
            snapshot = ids_engine.get_stats_snapshot()
            await manager.broadcast({"type": "stats", "data": snapshot})


@app.on_event("startup")
async def startup():
    await init_db()
    ids_engine.on_packet(on_packet)
    ids_engine.on_alert(on_alert)
    await ids_engine.start()
    asyncio.create_task(stats_broadcaster())
    asyncio.create_task(_periodic_db_flush())
    logger.info("IDS system ready — live capture mode")


@app.on_event("shutdown")
async def shutdown():
    # Flush any remaining buffered writes
    await _flush_event_batch()
    await _flush_alert_batch()
    await ids_engine.stop()


# ─── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    return {
        "status": "running" if ids_engine.is_running else "stopped",
        **ids_engine.get_stats_snapshot(),
    }


@app.get("/api/stats")
async def get_stats():
    return ids_engine.get_stats_snapshot()


@app.get("/api/events")
async def get_events(
    limit: int = Query(default=100, le=500),
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(NetworkEvent).order_by(desc(NetworkEvent.timestamp)).limit(limit)

    filters = []
    if severity:
        filters.append(NetworkEvent.severity == severity)
    if protocol:
        filters.append(NetworkEvent.protocol == protocol)
    if src_ip:
        filters.append(NetworkEvent.src_ip == src_ip)
    if filters:
        query = query.where(and_(*filters))

    result = await db.execute(query)
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat(),
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "src_port": e.src_port,
            "dst_port": e.dst_port,
            "protocol": e.protocol,
            "packet_size": e.packet_size,
            "severity": e.severity,
            "attack_type": e.attack_type,
            "description": e.description,
            "flags": e.flags,
            "ttl": e.ttl,
        }
        for e in events
    ]


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(default=50, le=200),
    severity: Optional[str] = None,
    unacknowledged: bool = False,
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert).order_by(desc(Alert.timestamp)).limit(limit)
    filters = []
    if severity:
        filters.append(Alert.severity == severity)
    if unacknowledged:
        filters.append(Alert.is_acknowledged == 0)
    if filters:
        query = query.where(and_(*filters))

    result = await db.execute(query)
    alerts = result.scalars().all()
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "alert_type": a.alert_type,
            "severity": a.severity,
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "description": a.description,
            "is_acknowledged": bool(a.is_acknowledged),
        }
        for a in alerts
    ]


@app.patch("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = 1
    await db.commit()
    return {"acknowledged": True}


@app.get("/api/analytics/timeline")
async def get_timeline(hours: int = Query(default=1, le=24), db: AsyncSession = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(NetworkEvent.severity, func.count(NetworkEvent.id))
        .where(NetworkEvent.timestamp >= since)
        .group_by(NetworkEvent.severity)
    )
    rows = result.all()
    return {row[0]: row[1] for row in rows}


@app.post("/api/control/start")
async def start_capture():
    if not ids_engine.is_running:
        await ids_engine.start()
    return {"status": "started"}


@app.post("/api/control/stop")
async def stop_capture():
    if ids_engine.is_running:
        await ids_engine.stop()
    return {"status": "stopped"}


@app.post("/api/control/reset")
async def reset_stats():
    """Reset all internal counters and statistics."""
    ids_engine.stats = {
        "total_packets": 0,
        "info_count": 0,
        "suspicious_count": 0,
        "malicious_count": 0,
        "start_time": datetime.utcnow(),
        "protocols": defaultdict(int),
        "top_src_ips": defaultdict(int),
        "alerts_today": 0,
    }
    ids_engine._bandwidth_window.clear()

    global recent_packets, recent_alerts, _event_batch, _alert_batch
    recent_packets.clear()
    recent_alerts.clear()
    _event_batch.clear()
    _alert_batch.clear()

    return {"status": "reset"}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)

    try:
        await websocket.send_text(json.dumps({
            "type": "init",
            "data": {
                "recent_packets": recent_packets[-50:],
                "recent_alerts": recent_alerts[-20:],
                "stats": ids_engine.get_stats_snapshot(),
            }
        }, default=str))
    except Exception:
        pass

    try:
        while True:
            await asyncio.sleep(30)
            try:
                await websocket.send_text(json.dumps({"type": "ping"}))
            except Exception:
                break
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)