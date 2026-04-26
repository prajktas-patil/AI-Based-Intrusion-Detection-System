from __future__ import annotations

import smtplib
from collections import defaultdict, deque
from datetime import datetime
from email.mime.text import MIMEText
from typing import Deque, Dict

import requests

from config_enhanced import enhanced_settings
from firewall_manager import FirewallManager
from forensic_logger import ForensicLogger
from models import Incident


class EnhancedAlertManager:
    def __init__(self) -> None:
        self.firewall = FirewallManager()
        self.forensic = ForensicLogger()
        self.last_alert_at_by_ip: Dict[str, datetime] = {}
        self.recent_incidents: Deque[Incident] = deque(maxlen=5000)
        self.alert_counts_by_ip = defaultdict(int)

    def handle_incident(self, incident: Incident) -> Incident:
        now = datetime.utcnow()
        src_ip = incident.event.src_ip
        last = self.last_alert_at_by_ip.get(src_ip)
        if last is not None and (now - last).total_seconds() < enhanced_settings.alert_cooldown_seconds:
            return incident

        incident.attack_pattern = self._detect_pattern(incident)
        incident.geo_country = self._geo_lookup_country(src_ip)
        self.last_alert_at_by_ip[src_ip] = now
        self.alert_counts_by_ip[src_ip] += 1
        self.recent_incidents.append(incident)
        self.forensic.log_incident(incident)

        self._send_notifications(incident)

        if self._should_block(incident):
            result = self.firewall.block_ip(src_ip, f"{incident.severity.value}:{incident.attack_pattern}")
            incident.blocked = result["blocked"]
            incident.block_expires_at = datetime.fromisoformat(result["expires_at"])
        return incident

    def unblock_ip(self, ip: str) -> bool:
        return self.firewall.unblock_ip(ip)

    def get_blocked_ips(self) -> list[dict]:
        return self.firewall.list_blocked()

    def _should_block(self, incident: Incident) -> bool:
        if not enhanced_settings.auto_block_enabled:
            return False
        src_ip = incident.event.src_ip
        if src_ip in enhanced_settings.whitelist_ip_set:
            return False
        return incident.severity.value in enhanced_settings.block_on_severity_set

    def _detect_pattern(self, incident: Incident) -> str:
        dst_port = incident.event.dst_port
        src_ip = incident.event.src_ip
        if dst_port in [22, 23, 3389] and incident.severity.value in {"HIGH", "CRITICAL"}:
            return "BRUTE_FORCE_ATTEMPT"
        if incident.event.packet_count > 120:
            return "POSSIBLE_DDOS_BURST"
        if self.alert_counts_by_ip[src_ip] >= 5:
            return "PERSISTENT_ATTACKER"
        if dst_port in [8080, 8443] and incident.anomaly_score < -0.6:
            return "SUSPICIOUS_WEB_TRAFFIC"
        return "UNKNOWN"

    @staticmethod
    def _geo_lookup_country(ip: str) -> str:
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
            return "PRIVATE_NET"
        try:
            # Public API; failures are non-blocking.
            resp = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=2)
            if resp.ok and resp.text.strip():
                return resp.text.strip()
        except requests.RequestException:
            pass
        return "UNKNOWN"

    def _send_notifications(self, incident: Incident) -> None:
        self._send_telegram(incident)
        self._send_email(incident)
        self._send_sms_stub(incident)

    def _send_telegram(self, incident: Incident) -> None:
        if not enhanced_settings.telegram_enabled:
            return
        token = enhanced_settings.telegram_bot_token
        chat_ids = enhanced_settings.telegram_chat_id_list
        if not token or not chat_ids:
            return
        text = (
            f"Security Alert: {incident.severity.value}\n"
            f"Pattern: {incident.attack_pattern}\n"
            f"Source: {incident.event.src_ip}:{incident.event.src_port}\n"
            f"Destination: {incident.event.dst_ip}:{incident.event.dst_port}\n"
            f"Score: {incident.anomaly_score:.4f}"
        )
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        for cid in chat_ids:
            try:
                requests.post(url, json={"chat_id": cid, "text": text}, timeout=3)
            except requests.RequestException:
                continue

    def _send_email(self, incident: Incident) -> None:
        if not enhanced_settings.email_enabled:
            return
        if not enhanced_settings.email_recipient_list:
            return
        if not enhanced_settings.email_smtp_server:
            return

        body = (
            f"Severity: {incident.severity.value}\n"
            f"Pattern: {incident.attack_pattern}\n"
            f"Source: {incident.event.src_ip}\n"
            f"Destination: {incident.event.dst_ip}\n"
            f"Score: {incident.anomaly_score:.4f}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = f"[SentinelMesh] {incident.severity.value} incident"
        msg["From"] = enhanced_settings.email_sender
        msg["To"] = ",".join(enhanced_settings.email_recipient_list)
        try:
            with smtplib.SMTP(enhanced_settings.email_smtp_server, enhanced_settings.email_smtp_port, timeout=5) as server:
                server.starttls()
                server.login(enhanced_settings.email_sender, enhanced_settings.email_password)
                server.sendmail(
                    enhanced_settings.email_sender,
                    enhanced_settings.email_recipient_list,
                    msg.as_string(),
                )
        except Exception:
            return

    def _send_sms_stub(self, incident: Incident) -> None:
        # Placeholder hook for Twilio integration.
        if enhanced_settings.sms_enabled and incident.severity.value == "CRITICAL":
            _ = incident.incident_id
