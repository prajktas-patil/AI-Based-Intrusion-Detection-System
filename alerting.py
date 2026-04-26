from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

import requests

from models import Incident, Severity
from security_config import settings


class AlertManager:
    severity_order = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }

    def __init__(self) -> None:
        self.last_alert_at_by_ip: Dict[str, datetime] = {}
        self.blocked_ips: Dict[str, datetime] = {}
        self.alert_counts_by_ip = defaultdict(int)

    def handle_incident(self, incident: Incident) -> Incident:
        src_ip = incident.event.src_ip
        now = datetime.utcnow()
        if self._is_cooldown(src_ip, now):
            return incident

        self.alert_counts_by_ip[src_ip] += 1
        self.last_alert_at_by_ip[src_ip] = now
        self._send_notifications(incident)

        if self._should_auto_block(incident):
            expires = now + timedelta(minutes=settings.block_duration_minutes)
            self.blocked_ips[src_ip] = expires
            incident.blocked = True
            incident.block_expires_at = expires
        return incident

    def unblock_expired(self) -> None:
        now = datetime.utcnow()
        expired = [ip for ip, expiry in self.blocked_ips.items() if expiry <= now]
        for ip in expired:
            del self.blocked_ips[ip]

    def _is_cooldown(self, src_ip: str, now: datetime) -> bool:
        last = self.last_alert_at_by_ip.get(src_ip)
        if last is None:
            return False
        delta = now - last
        return delta.total_seconds() < settings.alert_cooldown_seconds

    def _should_auto_block(self, incident: Incident) -> bool:
        if not settings.auto_block_enabled:
            return False
        if incident.event.src_ip in settings.whitelist_ip_set:
            return False
        threshold = Severity(settings.auto_block_min_severity)
        return self.severity_order[incident.severity] >= self.severity_order[threshold]

    def _send_notifications(self, incident: Incident) -> None:
        if settings.telegram_enabled:
            self._send_telegram(incident)

    @staticmethod
    def _send_telegram(incident: Incident) -> None:
        if not settings.telegram_bot_token or not settings.telegram_chat_id:
            return
        message = (
            f"SentinelMesh Alert: {incident.severity.value}\n"
            f"Source: {incident.event.src_ip}:{incident.event.src_port}\n"
            f"Destination: {incident.event.dst_ip}:{incident.event.dst_port}\n"
            f"Score: {incident.anomaly_score:.4f}\n"
            f"Action: {incident.recommended_action}"
        )
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
        try:
            requests.post(url, json={"chat_id": settings.telegram_chat_id, "text": message}, timeout=4)
        except requests.RequestException:
            pass

    def blocked_ip_list(self) -> List[dict]:
        return [
            {"ip": ip, "expires_at": expiry.isoformat()}
            for ip, expiry in sorted(self.blocked_ips.items(), key=lambda x: x[1])
        ]
