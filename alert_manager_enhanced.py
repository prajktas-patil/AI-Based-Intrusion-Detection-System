"""
AI Network Security Guard - Enhanced Alert Manager
Manages security alerts with auto-blocking and enhanced notifications
"""

import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Lock

try:
    from utils_enhanced import (
        logger, log_alert, log_forensic_data,
        send_email_alert, send_telegram_alert, send_slack_alert, 
        send_sms_alert, play_alert_sound
    )
    from config_enhanced import DETECTION_CONFIG, NOTIFICATION_CONFIG, get_severity_from_score
    from firewall_manager import FirewallManager
    FIREWALL_ENABLED = True
except ImportError:
    from utils import (
        logger, log_alert, 
        send_email_alert, send_slack_alert, play_alert_sound
    )
    from config import DETECTION_CONFIG, NOTIFICATION_CONFIG, get_severity_from_score
    FIREWALL_ENABLED = False


class EnhancedAlertManager:
    """
    Enhanced Alert Manager with Auto-Blocking and Multi-Channel Notifications
    """
    
    def __init__(self, max_alerts=1000):
        """
        Initialize Enhanced Alert Manager
        
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
            'blocked_ips': 0,
            'notifications_sent': 0,
        }
        
        # Alert deduplication tracking
        self.recent_alerts = {}  # key -> last_alert_time
        self.cooldown = DETECTION_CONFIG.get('alert_cooldown', 1.0)
        
        # Alert correlation
        self.src_ip_alerts = defaultdict(list)
        self.dst_ip_alerts = defaultdict(list)
        self.protocol_alerts = defaultdict(list)
        
        # IP tracking for auto-blocking
        self.ip_alert_counts = defaultdict(lambda: {'count': 0, 'first_seen': None, 'last_seen': None})
        
        # Initialize firewall manager
        self.firewall = None
        if FIREWALL_ENABLED:
            try:
                self.firewall = FirewallManager()
                logger.info("🔥 Firewall Manager integrated with Alert Manager")
            except Exception as e:
                logger.error(f"Failed to initialize Firewall Manager: {e}")
        
        logger.info(f"🚨 Enhanced Alert Manager initialized (max alerts: {max_alerts})")
    
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
            'blocked': False,  # Will be set if IP is auto-blocked
        }
        
        return alert
    
    def add_alert(self, alert):
        """
        Add alert to the system with deduplication and auto-blocking
        
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
            
            # Update IP tracking
            src_ip = alert['src_ip']
            self.ip_alert_counts[src_ip]['count'] += 1
            self.ip_alert_counts[src_ip]['last_seen'] = datetime.now()
            if self.ip_alert_counts[src_ip]['first_seen'] is None:
                self.ip_alert_counts[src_ip]['first_seen'] = datetime.now()
            
            # Update deduplication tracker
            self.recent_alerts[dedup_key] = datetime.now()
        
        # Log alert
        log_alert(alert)
        
        # 🆕 Check for auto-blocking
        self._check_auto_block(alert)
        
        # Send notifications
        self._handle_notifications(alert)
        
        logger.info(f"🚨 {alert['severity']} alert added: {alert['protocol']} "
                   f"{alert['src_ip']} → {alert['dst_ip']}")
        
        return True
    
    def _check_auto_block(self, alert):
        """
        🆕 Check if IP should be automatically blocked
        
        Args:
            alert: Alert information
        """
        if not self.firewall:
            return
        
        try:
            from config_enhanced import FIREWALL_CONFIG
            
            src_ip = alert['src_ip']
            severity = alert['severity']
            
            # Get alert count for this IP
            alert_count = self.ip_alert_counts[src_ip]['count']
            
            # Check if we should block
            should_block, reason = self.firewall.should_block_ip(src_ip, severity, alert_count)
            
            if should_block:
                # Attempt to block the IP
                success = self.firewall.block_ip(src_ip, severity, reason)
                
                if success:
                    alert['blocked'] = True
                    self.stats['blocked_ips'] += 1
                    
                    # Send notification about the block
                    if FIREWALL_CONFIG.get('notify_on_block', True):
                        self._notify_ip_blocked(alert, reason)
                    
                    logger.warning(f"🚫 AUTO-BLOCKED: {src_ip} | {reason}")
                    
        except Exception as e:
            logger.error(f"Error in auto-block check: {e}")
    
    def _notify_ip_blocked(self, alert, reason):
        """
        🆕 Send notification that an IP was auto-blocked
        
        Args:
            alert: Alert that triggered the block
            reason: Reason for blocking
        """
        # Create block notification
        block_alert = alert.copy()
        block_alert['severity'] = 'CRITICAL'  # Always send as critical
        block_alert['block_reason'] = reason
        
        # Send to all enabled channels
        try:
            if NOTIFICATION_CONFIG.get('telegram_enabled', False):
                self._send_telegram_block_notification(block_alert, reason)
            
            if NOTIFICATION_CONFIG.get('email_enabled', False):
                send_email_alert(block_alert)
            
            if NOTIFICATION_CONFIG.get('slack_enabled', False):
                send_slack_alert(block_alert)
                
        except Exception as e:
            logger.error(f"Error sending block notification: {e}")
    
    def _send_telegram_block_notification(self, alert, reason):
        """Send Telegram notification about blocked IP"""
        try:
            from utils_enhanced import send_telegram_alert
            
            # Override the message for block notification
            bot_token = NOTIFICATION_CONFIG['telegram_bot_token']
            chat_ids = NOTIFICATION_CONFIG['telegram_chat_ids']
            
            message = f"""
🔴 <b>IP ADDRESS BLOCKED!</b>

🚫 <b>Blocked IP:</b> <code>{alert['src_ip']}</code>
⚠️ <b>Reason:</b> {reason}

📊 <b>Alert Details:</b>
• Severity: {alert['severity']}
• Protocol: {alert['protocol']}
• Destination: <code>{alert.get('dst_ip', 'Unknown')}</code>
• Anomaly Score: {alert.get('anomaly_score', 'N/A'):.4f}

🔥 <b>Firewall Action:</b> IP has been automatically blocked
⏰ <b>Time:</b> {alert['timestamp']}

⚠️ This IP has been added to the firewall blocklist.
"""
            
            for chat_id in chat_ids:
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {
                    'chat_id': chat_id,
                    'text': message,
                    'parse_mode': 'HTML'
                }
                requests.post(url, json=payload)
                
        except Exception as e:
            logger.error(f"Error sending Telegram block notification: {e}")
    
    def _handle_notifications(self, alert):
        """Handle alert notifications based on severity"""
        severity = alert['severity']
        sent_count = 0
        
        try:
            # Email notification
            if NOTIFICATION_CONFIG.get('email_enabled', False):
                if severity in NOTIFICATION_CONFIG.get('email_on_severity', []):
                    if send_email_alert(alert):
                        sent_count += 1
            
            # 🆕 Telegram notification
            if NOTIFICATION_CONFIG.get('telegram_enabled', False):
                if severity in NOTIFICATION_CONFIG.get('telegram_on_severity', []):
                    try:
                        from utils_enhanced import send_telegram_alert
                        if send_telegram_alert(alert):
                            sent_count += 1
                    except ImportError:
                        pass
            
            # Slack notification
            if NOTIFICATION_CONFIG.get('slack_enabled', False):
                if severity in NOTIFICATION_CONFIG.get('slack_on_severity', []):
                    if send_slack_alert(alert):
                        sent_count += 1
            
            # 🆕 SMS notification
            if NOTIFICATION_CONFIG.get('sms_enabled', False):
                if severity in NOTIFICATION_CONFIG.get('sms_on_severity', []):
                    try:
                        from utils_enhanced import send_sms_alert
                        if send_sms_alert(alert):
                            sent_count += 1
                    except ImportError:
                        pass
            
            # Sound alert
            if NOTIFICATION_CONFIG.get('sound_enabled', False):
                if severity in NOTIFICATION_CONFIG.get('sound_on_severity', []):
                    play_alert_sound()
            
            if sent_count > 0:
                self.stats['notifications_sent'] += sent_count
                logger.debug(f"Sent {sent_count} notification(s) for {severity} alert")
                
        except Exception as e:
            logger.error(f"Error handling notifications: {e}")
    
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
        """Get alert and firewall statistics"""
        stats = self.stats.copy()
        
        # Add firewall statistics if available
        if self.firewall:
            fw_stats = self.firewall.get_statistics()
            stats['firewall'] = fw_stats
            stats['currently_blocked_ips'] = len(self.firewall.get_blocked_ips())
        
        return stats
    
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
                    'severity': 'HIGH',
                    'ip': ip
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
    
    def get_blocked_ips(self):
        """🆕 Get list of currently blocked IPs"""
        if self.firewall:
            return self.firewall.get_blocked_ips()
        return []
    
    def unblock_ip(self, ip_address):
        """🆕 Manually unblock an IP address"""
        if self.firewall:
            return self.firewall.unblock_ip(ip_address)
        return False
    
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
        summary.append(f"🚫 Blocked IPs: {stats.get('blocked_ips', 0)}")
        summary.append(f"📱 Notifications Sent: {stats.get('notifications_sent', 0)}")
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
                blocked_status = " [BLOCKED]" if self.firewall and ip in self.firewall.get_blocked_ips() else ""
                summary.append(f"  • {ip}: {count} alerts{blocked_status}")
        
        summary.append("=" * 70)
        
        return "\n".join(summary)


# For backward compatibility
AlertManager = EnhancedAlertManager


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'EnhancedAlertManager',
    'AlertManager',
]
