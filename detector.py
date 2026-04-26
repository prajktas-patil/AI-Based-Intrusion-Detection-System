"""
detector.py  –  DetectorService wraps the trained IsolationForest model.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import settings
from models import AttackType, Incident, NetworkEvent, Severity

FEATURE_COLUMNS = [
    "bytes_sent",
    "bytes_received",
    "duration_ms",
    "packet_count",
    "src_port",
    "dst_port",
]

# Ports frequently targeted in real attacks
BRUTE_FORCE_PORTS   = {22, 23, 3389, 5900, 21, 25, 110}
SUSPICIOUS_WEB_PORTS = {8080, 8443, 8888, 4444, 1337}
DNS_PORT            = 53

# MITRE ATT&CK tactic quick-map
ATTACK_MITRE: dict[AttackType, str] = {
    AttackType.PORT_SCAN:          "TA0007 – Discovery",
    AttackType.BRUTE_FORCE:        "TA0006 – Credential Access",
    AttackType.DOS_ATTACK:         "TA0040 – Impact",
    AttackType.DDOS_BURST:         "TA0040 – Impact",
    AttackType.DATA_EXFILTRATION:  "TA0010 – Exfiltration",
    AttackType.C2_BEACON:          "TA0011 – Command and Control",
    AttackType.SUSPICIOUS_WEB:     "TA0001 – Initial Access",
    AttackType.PERSISTENT_ATTACKER:"TA0003 – Persistence",
    AttackType.UNKNOWN_ANOMALY:    "TA0043 – Reconnaissance",
}


class DetectorService:
    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self.total_events: int = 0
        self.model_loaded: bool = False
        self.model_source: str = "none"

    # ─── loading ────────────────────────────────────────────────────────

    def load(self) -> None:
        model_file  = Path(settings.model_path)
        scaler_file = Path(settings.scaler_path)
        source_file = Path(settings.model_source_path)

        if model_file.exists() and scaler_file.exists():
            self.model  = joblib.load(model_file)
            self.scaler = joblib.load(scaler_file)
            self.model_source = source_file.read_text().strip() if source_file.exists() else "unknown"
            self.model_loaded = True
            return

        # First-run: auto-train with synthetic data so the app is immediately usable
        print("[Detector] No saved model found – running quick auto-train …")
        from trainer import train
        self.model_source = train()
        self.model  = joblib.load(model_file)
        self.scaler = joblib.load(scaler_file)
        self.model_loaded = True

    # ─── detection ──────────────────────────────────────────────────────

    def detect(self, event: NetworkEvent, count_event: bool = True) -> Incident | None:
        if count_event:
            self.total_events += 1
        if not self.model_loaded or self.model is None or self.scaler is None:
            return None

        vector = np.array([[
            event.bytes_sent,
            event.bytes_received,
            event.duration_ms,
            event.packet_count,
            event.src_port,
            event.dst_port,
        ]], dtype=float)

        scaled = self.scaler.transform(vector)
        score  = float(self.model.decision_function(scaled)[0])

        if score >= settings.anomaly_threshold:
            return None  # normal traffic

        severity   = self._to_severity(score)
        confidence = min(1.0, abs(score) / max(abs(settings.critical_threshold), 1e-9))
        attack_type = self._classify_attack(event)
        mitre_tactic = ATTACK_MITRE.get(attack_type, "")

        return Incident(
            incident_id        = f"inc_{uuid4().hex[:12]}",
            timestamp          = datetime.utcnow(),
            severity           = severity,
            anomaly_score      = round(score, 6),
            confidence         = round(confidence, 3),
            title              = f"{severity.value} – {attack_type.value.replace('_', ' ').title()}",
            description        = (
                f"Anomalous traffic from {event.src_ip}:{event.src_port} "
                f"→ {event.dst_ip}:{event.dst_port}  [{event.protocol}]  "
                f"score={score:.4f}"
            ),
            recommended_action = self._recommend(severity, attack_type),
            event              = event,
            attack_type        = attack_type,
            attack_pattern     = attack_type.value,
            mitre_tactic       = mitre_tactic,
        )

    # ─── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _to_severity(score: float) -> Severity:
        if score <= settings.critical_threshold:
            return Severity.CRITICAL
        if score <= settings.high_threshold:
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _classify_attack(event: NetworkEvent) -> AttackType:
        dst = event.dst_port
        pkt = event.packet_count

        # DDoS / DoS – very high packet counts
        if pkt > 500:
            return AttackType.DDOS_BURST
        if pkt > 150:
            return AttackType.DOS_ATTACK

        # Brute-force – common auth ports
        if dst in BRUTE_FORCE_PORTS:
            return AttackType.BRUTE_FORCE

        # Port scan heuristic – tiny payload + unusual high port
        if event.bytes_sent < 80 and event.bytes_received < 80 and dst > 49000:
            return AttackType.PORT_SCAN

        # Data exfiltration – huge outbound, low inbound, long duration
        if event.bytes_sent > 50_000 and event.bytes_sent > event.bytes_received * 10:
            return AttackType.DATA_EXFILTRATION

        # C2 beaconing – regular small packets to non-standard port
        if 100 < pkt < 500 and event.bytes_sent < 500 and dst not in {80, 443, 53}:
            return AttackType.C2_BEACON

        # Suspicious web traffic
        if dst in SUSPICIOUS_WEB_PORTS:
            return AttackType.SUSPICIOUS_WEB

        return AttackType.UNKNOWN_ANOMALY

    @staticmethod
    def _recommend(severity: Severity, attack: AttackType) -> str:
        tips = {
            AttackType.BRUTE_FORCE:        "Block source IP; enforce MFA; check auth logs.",
            AttackType.PORT_SCAN:          "Block source IP; audit exposed service ports.",
            AttackType.DDOS_BURST:         "Rate-limit source; enable upstream scrubbing.",
            AttackType.DOS_ATTACK:         "Rate-limit source; alert upstream provider.",
            AttackType.DATA_EXFILTRATION:  "Isolate host immediately; capture full PCAP.",
            AttackType.C2_BEACON:          "Isolate host; inspect running processes; block C2 IP.",
            AttackType.SUSPICIOUS_WEB:     "Inspect HTTP payload; check for web shells.",
            AttackType.PERSISTENT_ATTACKER:"Review historical logs; escalate to SOC.",
            AttackType.UNKNOWN_ANOMALY:    "Review connection context; escalate if pattern repeats.",
        }
        base = tips.get(attack, "Investigate and escalate if behaviour persists.")
        if severity == Severity.CRITICAL:
            base = "⚠ CRITICAL – " + base
        return base
