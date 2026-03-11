"""
AI Network Security Guard - Alert Manager
Manages security alerts, notifications, and alert correlation
"""

import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock
from utils import logger, log_alert, send_email_alert, send_slack_alert, play_alert_sound
from config import DETECTION_CONFIG, NOTIFICATION_CONFIG, get_severity_from_score

class AlertManager:
    """
    Manages security alerts with deduplication, correlation, and notification
    """
    
    def __init__(self, max_alerts=1000):
        """
        Initialize Alert Manager
        
        Args:
            max_alerts: Maximum number of alerts to keep in memory
        """
        self.max_alerts = max_alerts
        self.alerts = deque(maxlen=max_alerts)
        self.alert_lock = Lock()
        
        # Alert statistics
        self.stats = {
            'total_alerts': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
        }
        
        # Alert deduplication tracking
        self.recent_alerts = {}  # key -> last_alert_time
        self.cooldown = DETECTION_CONFIG.get('alert_cooldown', 1.0)
        
        # Alert correlation
        self.src_ip_alerts = defaultdict(list)
        self.dst_ip_alerts = defaultdict(list)
        self.protocol_alerts = defaultdict(list)
        
        logger.info(f"🚨 Alert Manager initialized (max alerts: {max_alerts})")
    
    def create_alert(self, packet_data, anomaly_score, severity=None):
        """
        Create a new security alert
        
        Args:
            packet_data: Dictionary containing packet information
            anomaly_score: Anomaly score from the model
            severity: Alert severity (auto-calculated if None)
            
        Returns:
            Alert dictionary
        """
        if severity is None:
            severity = get_severity_from_score(anomaly_score)
        
        alert = {
            'id': f"alert_{int(time.time() * 1000)}_{self.stats['total_alerts']}",
            'timestamp': datetime.now(),
            'severity': severity,
            'protocol': packet_data.get('protocol', 'Unknown'),
            'src_ip': packet_data.get('src_ip', 'Unknown'),
            'dst_ip': packet_data.get('dst_ip', 'Unknown'),
            'src_port': packet_data.get('src_port', 0),
            'dst_port': packet_data.get('dst_port', 0),
            'anomaly_score': round(anomaly_score, 4),
            'packet_size': packet_data.get('src_bytes', 0),
            'duration': packet_data.get('duration', 0),
            'connection_count': packet_data.get('count', 1),
        }
        
        return alert
    
    def add_alert(self, alert):
        """
        Add alert to the system with deduplication
        
        Args:
            alert: Alert dictionary
            
        Returns:
            True if alert was added, False if deduplicated
        """
        # Create deduplication key
        dedup_key = f"{alert['src_ip']}:{alert['dst_ip']}:{alert['protocol']}"
        
        # Check if similar alert was recently sent
        if dedup_key in self.recent_alerts:
            last_time = self.recent_alerts[dedup_key]
            if (datetime.now() - last_time).total_seconds() < self.cooldown:
                logger.debug(f"Alert deduplicated: {dedup_key}")
                return False
        
        # Add alert
        with self.alert_lock:
            self.alerts.append(alert)
            
            # Update statistics
            self.stats['total_alerts'] += 1
            severity_key = alert['severity'].lower()
            if severity_key in self.stats:
                self.stats[severity_key] += 1
            
            # Update correlation tracking
            self.src_ip_alerts[alert['src_ip']].append(alert)
            self.dst_ip_alerts[alert['dst_ip']].append(alert)
            self.protocol_alerts[alert['protocol']].append(alert)
            
            # Update deduplication tracker
            self.recent_alerts[dedup_key] = datetime.now()
        
        # Log alert
        log_alert(alert)
        
        # Send notifications
        self._handle_notifications(alert)
        
        logger.info(f"🚨 {alert['severity']} alert added: {alert['protocol']} "
                   f"{alert['src_ip']} → {alert['dst_ip']}")
        
        return True
    
    def _handle_notifications(self, alert):
        """Handle alert notifications based on severity"""
        severity = alert['severity']
        
        # Email notification
        if NOTIFICATION_CONFIG['email_enabled']:
            if severity in NOTIFICATION_CONFIG['email_on_severity']:
                send_email_alert(alert)
        
        # Slack notification
        if NOTIFICATION_CONFIG['slack_enabled']:
            if severity in NOTIFICATION_CONFIG['slack_on_severity']:
                send_slack_alert(alert)
        
        # Sound alert
        if NOTIFICATION_CONFIG['sound_enabled']:
            if severity in NOTIFICATION_CONFIG['sound_on_severity']:
                play_alert_sound()
    
    def get_recent_alerts(self, count=50):
        """Get most recent alerts"""
        with self.alert_lock:
            return list(self.alerts)[-count:]
    
    def get_alerts_by_severity(self, severity):
        """Get all alerts of a specific severity"""
        with self.alert_lock:
            return [a for a in self.alerts if a['severity'] == severity]
    
    def get_alerts_by_ip(self, ip, ip_type='src'):
        """
        Get alerts involving a specific IP
        
        Args:
            ip: IP address
            ip_type: 'src' or 'dst'
        """
        if ip_type == 'src':
            return self.src_ip_alerts.get(ip, [])
        else:
            return self.dst_ip_alerts.get(ip, [])
    
    def get_alerts_by_protocol(self, protocol):
        """Get alerts for a specific protocol"""
        return self.protocol_alerts.get(protocol, [])
    
    def get_alerts_in_timerange(self, start_time, end_time=None):
        """
        Get alerts within a time range
        
        Args:
            start_time: Start datetime
            end_time: End datetime (default: now)
        """
        if end_time is None:
            end_time = datetime.now()
        
        with self.alert_lock:
            return [
                a for a in self.alerts
                if start_time <= a['timestamp'] <= end_time
            ]
    
    def get_statistics(self):
        """Get alert statistics"""
        return self.stats.copy()
    
    def analyze_attack_pattern(self, time_window_minutes=10):
        """
        Analyze recent alerts for attack patterns
        
        Args:
            time_window_minutes: Time window to analyze
            
        Returns:
            Dictionary of detected patterns
        """
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
        recent = self.get_alerts_in_timerange(cutoff_time)
        
        if not recent:
            return {'patterns': [], 'risk_level': 'LOW'}
        
        patterns = []
        
        # Check for port scanning
        unique_dst_ports = len(set(a['dst_port'] for a in recent if a['dst_port']))
        if unique_dst_ports > 20:
            patterns.append({
                'type': 'PORT_SCAN',
                'description': f'Possible port scan detected ({unique_dst_ports} different ports)',
                'severity': 'HIGH'
            })
        
        # Check for DDoS indicators
        src_ips = [a['src_ip'] for a in recent]
        if len(src_ips) > 50:
            patterns.append({
                'type': 'DDOS',
                'description': f'Possible DDoS attack ({len(set(src_ips))} unique source IPs)',
                'severity': 'CRITICAL'
            })
        
        # Check for data exfiltration
        total_bytes = sum(a['packet_size'] for a in recent)
        if total_bytes > 10_000_000:  # 10 MB
            patterns.append({
                'type': 'DATA_EXFILTRATION',
                'description': f'Large data transfer detected ({total_bytes / 1_000_000:.2f} MB)',
                'severity': 'HIGH'
            })
        
        # Check for repeated attacks from same source
        src_ip_counts = defaultdict(int)
        for alert in recent:
            src_ip_counts[alert['src_ip']] += 1
        
        for ip, count in src_ip_counts.items():
            if count > 10:
                patterns.append({
                    'type': 'PERSISTENT_ATTACKER',
                    'description': f'Repeated attacks from {ip} ({count} alerts)',
                    'severity': 'HIGH'
                })
        
        # Determine overall risk level
        if any(p['severity'] == 'CRITICAL' for p in patterns):
            risk_level = 'CRITICAL'
        elif any(p['severity'] == 'HIGH' for p in patterns):
            risk_level = 'HIGH'
        elif patterns:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'patterns': patterns,
            'risk_level': risk_level,
            'alert_count': len(recent),
            'time_window': time_window_minutes
        }
    
    def get_top_attackers(self, n=10):
        """Get top N source IPs by alert count"""
        src_counts = defaultdict(int)
        
        with self.alert_lock:
            for alert in self.alerts:
                src_counts[alert['src_ip']] += 1
        
        return sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def get_top_targets(self, n=10):
        """Get top N destination IPs by alert count"""
        dst_counts = defaultdict(int)
        
        with self.alert_lock:
            for alert in self.alerts:
                dst_counts[alert['dst_ip']] += 1
        
        return sorted(dst_counts.items(), key=lambda x: x[1], reverse=True)[:n]
    
    def clear_old_alerts(self, hours=24):
        """
        Clear alerts older than specified hours
        
        Args:
            hours: Age threshold in hours
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.alert_lock:
            old_count = len(self.alerts)
            self.alerts = deque(
                (a for a in self.alerts if a['timestamp'] > cutoff_time),
                maxlen=self.max_alerts
            )
            new_count = len(self.alerts)
        
        removed = old_count - new_count
        if removed > 0:
            logger.info(f"🧹 Cleared {removed} old alerts (older than {hours}h)")
    
    def export_alerts_to_dict(self):
        """Export all alerts as a list of dictionaries"""
        with self.alert_lock:
            return [
                {
                    **alert,
                    'timestamp': alert['timestamp'].isoformat()
                }
                for alert in self.alerts
            ]
    
    def generate_alert_summary(self):
        """Generate a text summary of current alerts"""
        stats = self.get_statistics()
        patterns = self.analyze_attack_pattern()
        top_attackers = self.get_top_attackers(5)
        
        summary = []
        summary.append("=" * 70)
        summary.append("SECURITY ALERT SUMMARY")
        summary.append("=" * 70)
        summary.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append("")
        summary.append(f"Total Alerts: {stats['total_alerts']}")
        summary.append(f"  🔴 Critical: {stats['critical']}")
        summary.append(f"  🟠 High: {stats['high']}")
        summary.append(f"  🟡 Medium: {stats['medium']}")
        summary.append(f"  🟢 Low: {stats['low']}")
        summary.append("")
        summary.append(f"Current Risk Level: {patterns['risk_level']}")
        summary.append("")
        
        if patterns['patterns']:
            summary.append("Detected Attack Patterns:")
            for pattern in patterns['patterns']:
                summary.append(f"  • {pattern['type']}: {pattern['description']}")
            summary.append("")
        
        if top_attackers:
            summary.append("Top Attackers:")
            for ip, count in top_attackers:
                summary.append(f"  • {ip}: {count} alerts")
        
        summary.append("=" * 70)
        
        return "\n".join(summary)


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'AlertManager',
]
