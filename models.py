from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(str, Enum):
    NORMAL = "NORMAL"
    PORT_SCAN = "PORT_SCAN"
    BRUTE_FORCE = "BRUTE_FORCE"
    DOS_ATTACK = "DOS_ATTACK"
    DDOS_BURST = "DDOS_BURST"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SUSPICIOUS_WEB = "SUSPICIOUS_WEB"
    PERSISTENT_ATTACKER = "PERSISTENT_ATTACKER"
    C2_BEACON = "C2_BEACON"
    UNKNOWN_ANOMALY = "UNKNOWN_ANOMALY"


class NetworkEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    src_ip: str
    dst_ip: str
    protocol: str = "UNKNOWN"
    src_port: int = 0
    dst_port: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_ms: int = 0
    packet_count: int = 1
    flags: Optional[str] = None          # TCP flags string e.g. "SYN,ACK"
    ttl: Optional[int] = None
    iface: Optional[str] = None          # network interface


class Incident(BaseModel):
    incident_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: Severity
    anomaly_score: float
    confidence: float
    title: str
    description: str
    recommended_action: str
    event: NetworkEvent
    blocked: bool = False
    block_expires_at: Optional[datetime] = None
    attack_pattern: Optional[str] = None
    attack_type: Optional[AttackType] = AttackType.UNKNOWN_ANOMALY
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    threat_intel_hit: bool = False
    mitre_tactic: Optional[str] = None   # MITRE ATT&CK tactic tag


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_source: str          # "kaggle" | "synthetic"
    incidents_in_memory: int
    uptime_seconds: float


class MetricsResponse(BaseModel):
    total_events: int
    total_incidents: int
    blocked_ips: int
    top_attack_types: List[dict]
    detection_rate: float
