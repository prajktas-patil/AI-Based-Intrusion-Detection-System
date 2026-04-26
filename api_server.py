"""
api_server.py  –  SentinelMesh REST API

Endpoints:
  GET  /health
  GET  /metrics
  GET  /events
  GET  /incidents
  GET  /blocked-ips
  POST /simulate           – inject synthetic event
  POST /simulate/attack    – force specific attack type
  POST /ingest             – ingest a real NetworkEvent JSON
  POST /unblock/{ip}
  POST /train              – retrain model (async)
  POST /reports/generate
  GET  /capture/status     – live-capture status
  POST /capture/start      – start live capture thread
  POST /capture/stop       – stop live capture thread
"""

from __future__ import annotations

import threading
import time
import logging
from collections import deque
from datetime import datetime
from typing import Deque, List, Optional
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from alert_manager import AlertManager
from config import settings
from detector import DetectorService
from feature_extractor import FeatureExtractor
from forensic_logger import ForensicLogger
from models import HealthResponse, Incident, MetricsResponse, NetworkEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelmesh")

app = FastAPI(
    title="SentinelMesh API",
    version="2.0.0",
    description="AI-powered Network Intrusion Detection System",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared state ──────────────────────────────────────────────────────────────
detector      = DetectorService()
alert_manager = AlertManager()
extractor     = FeatureExtractor()
forensic      = ForensicLogger()
incidents:  Deque[Incident] = deque(maxlen=2000)
events:     Deque[dict]     = deque(maxlen=3000)

_start_time = time.time()
_capture_thread: Optional[threading.Thread] = None
_capture_stop   = threading.Event()
_capture_active = False


# ── Lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup() -> None:
    detector.load()
    logger.info(f"Model loaded. Source: {detector.model_source}")


# ── Health / Metrics ──────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": detector.model_loaded,
        "model_source": detector.model_source,
        "incidents_in_memory": len(incidents),
        "uptime_seconds": round(time.time() - _start_time, 1),
        "capture_active": _capture_active,
    }


@app.get("/metrics")
def metrics() -> dict:
    from collections import Counter
    all_inc = list(incidents)
    attack_counter = Counter(
        i.attack_type.value if i.attack_type else "UNKNOWN" for i in all_inc
    )
    total = detector.total_events or 1
    return {
        "total_events":    detector.total_events,
        "total_incidents": len(all_inc),
        "blocked_ips":     len(alert_manager.get_blocked_ips()),
        "top_attack_types": [
            {"type": k, "count": v} for k, v in attack_counter.most_common(5)
        ],
        "detection_rate": round(len(all_inc) / total, 4),
    }


# ── Events / Incidents ────────────────────────────────────────────────────────

@app.get("/events")
def list_events(limit: int = 100) -> List[dict]:
    return list(events)[-limit:]


@app.get("/incidents")
def list_incidents(limit: int = 100, severity: str | None = None) -> List[dict]:
    result = list(incidents)[-limit:]
    if severity:
        result = [i for i in result if i.severity.value == severity.upper()]
    return [i.model_dump(mode="json") for i in result]


@app.get("/blocked-ips")
def blocked_ips() -> List[dict]:
    return alert_manager.get_blocked_ips()


# ── Simulation ────────────────────────────────────────────────────────────────

@app.post("/simulate")
def simulate_event(force_anomaly: bool = False) -> dict:
    packet = extractor.simulated_packet()

    if force_anomaly:
        # Inject obvious attack characteristics
        packet["bytes_sent"]     = packet["bytes_sent"] * 5
        packet["duration_ms"]    = max(4000, packet["duration_ms"] * 4)
        packet["packet_count"]   = max(150, packet["packet_count"] * 3)
        packet["dst_port"]       = 22

    event = extractor.from_packet_dict(packet)
    forensic.log_telemetry(event.model_dump(mode="json"))
    incident = detector.detect(event)

    _record_event(event, incident)

    if incident is None:
        return {"result": "normal", "event": event.model_dump(mode="json")}

    handled = _handle(incident)
    return {"result": "incident", "incident": handled.model_dump(mode="json")}


class AttackSimRequest(BaseModel):
    attack_type: str = "BRUTE_FORCE"   # BRUTE_FORCE | DDOS | EXFIL | PORT_SCAN | C2


@app.post("/simulate/attack")
def simulate_attack(req: AttackSimRequest) -> dict:
    """Force a specific attack type for demo / testing."""
    atype = req.attack_type.upper()
    templates = {
        "BRUTE_FORCE": dict(dst_port=22,   packet_count=60,  bytes_sent=400,    bytes_received=100,  duration_ms=300),
        "DDOS":        dict(dst_port=80,   packet_count=800, bytes_sent=60000,  bytes_received=200,  duration_ms=2000),
        "EXFIL":       dict(dst_port=443,  packet_count=80,  bytes_sent=300000, bytes_received=300,  duration_ms=8000),
        "PORT_SCAN":   dict(dst_port=54321,packet_count=2,   bytes_sent=60,     bytes_received=40,   duration_ms=10),
        "C2":          dict(dst_port=4444, packet_count=200, bytes_sent=200,    bytes_received=200,  duration_ms=400),
    }
    overrides = templates.get(atype, templates["BRUTE_FORCE"])
    packet = extractor.simulated_packet()
    packet.update(overrides)
    event = extractor.from_packet_dict(packet)
    forensic.log_telemetry(event.model_dump(mode="json"))
    incident = detector.detect(event)

    # Force-create incident if model didn't flag it (demo safety)
    if incident is None:
        from models import AttackType, Severity
        incident = Incident(
            incident_id        = f"inc_demo_{uuid4().hex[:10]}",
            severity           = Severity.HIGH,
            anomaly_score      = -0.75,
            confidence         = 0.91,
            title              = f"Simulated {atype} Attack",
            description        = f"Demo-injected {atype} from {event.src_ip}",
            recommended_action = "This is a simulated event for demo/testing.",
            event              = event,
            attack_type        = AttackType[atype] if atype in AttackType.__members__ else AttackType.UNKNOWN_ANOMALY,
            attack_pattern     = atype,
        )

    _record_event(event, incident)
    handled = _handle(incident)
    return {"result": "incident", "attack_type": atype, "incident": handled.model_dump(mode="json")}


# ── Ingest real events ────────────────────────────────────────────────────────

@app.post("/ingest")
def ingest_event(event: NetworkEvent) -> dict:
    forensic.log_telemetry(event.model_dump(mode="json"))
    incident = detector.detect(event)
    _record_event(event, incident)
    if incident is None:
        return {"result": "normal"}
    handled = _handle(incident)
    return {"result": "incident", "incident": handled.model_dump(mode="json")}


# ── Firewall ──────────────────────────────────────────────────────────────────

@app.post("/unblock/{ip}")
def unblock(ip: str) -> dict:
    ok = alert_manager.unblock_ip(ip)
    if not ok:
        raise HTTPException(status_code=404, detail=f"{ip} not in blocked list")
    return {"unblocked": ip}


# ── Training ──────────────────────────────────────────────────────────────────

@app.post("/train")
def retrain(dataset_path: str = "") -> dict:
    """Retrain model. Pass dataset_path or set KAGGLE_IDS_DATASET env var."""
    import os
    from trainer import train
    if dataset_path:
        os.environ["KAGGLE_IDS_DATASET"] = dataset_path

    def _do_train():
        src = train()
        detector.load()
        logger.info(f"Model retrained. Source: {src}")

    t = threading.Thread(target=_do_train, daemon=True)
    t.start()
    return {"status": "training_started", "dataset_path": dataset_path or "synthetic"}


# ── Live Capture ──────────────────────────────────────────────────────────────

@app.get("/capture/status")
def capture_status() -> dict:
    return {
        "active":    _capture_active,
        "interface": settings.capture_interface,
        "scapy_available": _scapy_available(),
    }


@app.post("/capture/start")
def capture_start(interface: str = "") -> dict:
    global _capture_thread, _capture_active, _capture_stop
    if _capture_active:
        return {"status": "already_running"}

    _capture_stop.clear()
    iface = interface or settings.capture_interface

    def _run():
        global _capture_active
        _capture_active = True
        try:
            from packet_sniffer import FlowAggregator, PacketSnifferService
            from scapy.all import sniff as scapy_sniff, IP, TCP, UDP, ICMP

            def on_flow(event: NetworkEvent) -> None:
                """Called for EVERY flow — record it, then check for anomaly."""
                # Always count and log the event (normal or anomalous)
                detector.total_events += 1
                forensic.log_telemetry(event.model_dump(mode="json"))
                events.append({
                    "timestamp":  datetime.utcnow().isoformat(),
                    "src_ip":     event.src_ip,
                    "dst_ip":     event.dst_ip,
                    "protocol":   event.protocol,
                    "dst_port":   event.dst_port,
                    "bytes_sent": event.bytes_sent,
                    "packet_count": event.packet_count,
                    "result":     "normal",  # updated below if incident
                })
                # Run AI detection (don't double-count, we already incremented above)
                incident = detector.detect(event, count_event=False)
                if incident is not None:
                    # Update the last event entry to incident
                    if events:
                        events[-1]["result"] = "incident"
                    handled = _handle(incident)
                    incidents.append(handled)

            aggregator = FlowAggregator(on_flow=on_flow)

            def packet_cb(pkt):
                aggregator.add_packet(pkt)

            logger.info(f"Live capture started on interface: {iface}")
            scapy_sniff(
                iface=iface,
                prn=packet_cb,
                store=False,
                stop_filter=lambda _: _capture_stop.is_set(),
            )
        except Exception as exc:
            logger.error(f"Live capture error: {exc}")
        finally:
            _capture_active = False

    _capture_thread = threading.Thread(target=_run, daemon=True)
    _capture_thread.start()
    return {"status": "started", "interface": iface}


@app.post("/capture/stop")
def capture_stop() -> dict:
    global _capture_active
    _capture_stop.set()
    _capture_active = False
    return {"status": "stopping"}


# ── Reports ───────────────────────────────────────────────────────────────────

@app.post("/reports/generate")
def generate_report(hours: int = 24) -> dict:
    path = forensic.generate_report(list(incidents), hours=hours)
    return {"report_path": path, "incident_count": len(incidents)}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _handle(incident: Incident) -> Incident:
    try:
        return alert_manager.handle_incident(incident)
    except Exception as exc:
        logger.exception(f"Alert manager error: {exc}")
        return incident


def _record_event(event: NetworkEvent, incident: Optional[Incident]) -> None:
    events.append({
        "timestamp":  datetime.utcnow().isoformat(),
        "src_ip":     event.src_ip,
        "dst_ip":     event.dst_ip,
        "protocol":   event.protocol,
        "dst_port":   event.dst_port,
        "bytes_sent": event.bytes_sent,
        "result":     "incident" if incident else "normal",
    })
    if incident:
        incidents.append(incident)


def _scapy_available() -> bool:
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False
