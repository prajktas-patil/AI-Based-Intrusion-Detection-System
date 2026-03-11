"""
AI Network Security Guard - Utility Functions
Helper functions for logging, notifications, and data processing
"""

import logging
import pickle
import json
import os
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from config import LOGGING_CONFIG, NOTIFICATION_CONFIG, PATHS

# ============================================================================
# LOGGING UTILITIES
# ============================================================================

def setup_logger(name='network_guard'):
    """Setup and configure logger"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOGGING_CONFIG['log_level']))
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    
    # File handler
    log_file = os.path.join(PATHS['logs_dir'], LOGGING_CONFIG['log_file'])
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(LOGGING_CONFIG['log_format'])
    file_handler.setFormatter(file_formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

# Create global logger
logger = setup_logger()

# ============================================================================
# ALERT LOGGING
# ============================================================================

def log_alert(alert_data):
    """Log security alert to file"""
    alert_log_file = os.path.join(PATHS['logs_dir'], 'security_alerts.log')
    
    with open(alert_log_file, 'a') as f:
        log_entry = {
            'timestamp': alert_data.get('timestamp', datetime.now().isoformat()),
            'severity': alert_data.get('severity', 'UNKNOWN'),
            'protocol': alert_data.get('protocol', 'UNKNOWN'),
            'src_ip': alert_data.get('src_ip', 'UNKNOWN'),
            'dst_ip': alert_data.get('dst_ip', 'UNKNOWN'),
            'anomaly_score': alert_data.get('anomaly_score', 0),
            'packet_size': alert_data.get('packet_size', 0),
        }
        f.write(json.dumps(log_entry) + '\n')
    
    logger.warning(f"🚨 ALERT: {alert_data['severity']} - {alert_data['protocol']} "
                   f"from {alert_data.get('src_ip', 'unknown')} to {alert_data.get('dst_ip', 'unknown')}")

def read_alert_logs(limit=100):
    """Read recent alerts from log file"""
    alert_log_file = os.path.join(PATHS['logs_dir'], 'security_alerts.log')
    
    if not os.path.exists(alert_log_file):
        return []
    
    alerts = []
    with open(alert_log_file, 'r') as f:
        lines = f.readlines()
        for line in lines[-limit:]:
            try:
                alerts.append(json.loads(line.strip()))
            except:
                pass
    
    return alerts

# ============================================================================
# NOTIFICATION UTILITIES
# ============================================================================

def send_email_alert(alert_data):
    """Send email notification for security alert"""
    if not NOTIFICATION_CONFIG['email_enabled']:
        return False
    
    try:
        msg = MIMEMultipart()
        msg['From'] = NOTIFICATION_CONFIG['email_sender']
        msg['To'] = ', '.join(NOTIFICATION_CONFIG['email_recipients'])
        msg['Subject'] = f"🚨 Security Alert: {alert_data['severity']} - Network Anomaly Detected"
        
        body = f"""
        AI Network Security Guard Alert
        
        Severity: {alert_data['severity']}
        Time: {alert_data['timestamp']}
        Protocol: {alert_data['protocol']}
        Source IP: {alert_data.get('src_ip', 'Unknown')}
        Destination IP: {alert_data.get('dst_ip', 'Unknown')}
        Anomaly Score: {alert_data.get('anomaly_score', 'N/A')}
        Packet Size: {alert_data.get('packet_size', 'N/A')} bytes
        
        Action Required: Please investigate this anomaly immediately.
        
        ---
        AI Network Security Guard
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(NOTIFICATION_CONFIG['email_smtp_server'], 
                             NOTIFICATION_CONFIG['email_smtp_port'])
        server.starttls()
        server.login(NOTIFICATION_CONFIG['email_sender'], 
                    NOTIFICATION_CONFIG['email_password'])
        
        text = msg.as_string()
        server.sendmail(NOTIFICATION_CONFIG['email_sender'], 
                       NOTIFICATION_CONFIG['email_recipients'], 
                       text)
        server.quit()
        
        logger.info(f"📧 Email alert sent for {alert_data['severity']} severity")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False

def send_slack_alert(alert_data):
    """Send Slack notification for security alert"""
    if not NOTIFICATION_CONFIG['slack_enabled']:
        return False
    
    try:
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
        }
        
        message = {
            "text": f"{severity_emoji.get(alert_data['severity'], '⚪')} *Security Alert Detected*",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🛡️ Network Anomaly - {alert_data['severity']}"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Time:*\n{alert_data['timestamp']}"},
                        {"type": "mrkdwn", "text": f"*Protocol:*\n{alert_data['protocol']}"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{alert_data.get('src_ip', 'Unknown')}"},
                        {"type": "mrkdwn", "text": f"*Destination:*\n{alert_data.get('dst_ip', 'Unknown')}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Anomaly Score:* {alert_data.get('anomaly_score', 'N/A'):.3f}\n*Packet Size:* {alert_data.get('packet_size', 'N/A')} bytes"
                    }
                }
            ]
        }
        
        response = requests.post(
            NOTIFICATION_CONFIG['slack_webhook_url'],
            json=message,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            logger.info(f"💬 Slack alert sent for {alert_data['severity']} severity")
            return True
        else:
            logger.error(f"Slack alert failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")
        return False

def play_alert_sound():
    """Play sound alert for critical anomalies"""
    if not NOTIFICATION_CONFIG['sound_enabled']:
        return
    
    try:
        # Cross-platform sound alert
        import platform
        system = platform.system()
        
        if system == 'Windows':
            import winsound
            winsound.Beep(1000, 500)  # 1000Hz for 500ms
        elif system == 'Darwin':  # macOS
            os.system('afplay /System/Library/Sounds/Glass.aiff')
        elif system == 'Linux':
            os.system('paplay /usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga')
    except:
        pass  # Sound not critical, fail silently

# ============================================================================
# MODEL UTILITIES
# ============================================================================

def save_model(model, scaler, features, model_dir=None):
    """Save trained model and preprocessing objects"""
    if model_dir is None:
        model_dir = PATHS['models_dir']
    
    os.makedirs(model_dir, exist_ok=True)
    
    with open(os.path.join(model_dir, 'anomaly_model.pkl'), 'wb') as f:
        pickle.dump(model, f)
    
    with open(os.path.join(model_dir, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f)
    
    with open(os.path.join(model_dir, 'features.pkl'), 'wb') as f:
        pickle.dump(features, f)
    
    logger.info(f"💾 Model saved to {model_dir}")

def load_model(model_dir=None):
    """Load trained model and preprocessing objects"""
    if model_dir is None:
        model_dir = PATHS['models_dir']
    
    try:
        with open(os.path.join(model_dir, 'anomaly_model.pkl'), 'rb') as f:
            model = pickle.load(f)
        
        with open(os.path.join(model_dir, 'scaler.pkl'), 'rb') as f:
            scaler = pickle.load(f)
        
        with open(os.path.join(model_dir, 'features.pkl'), 'rb') as f:
            features = pickle.load(f)
        
        logger.info(f"📦 Model loaded from {model_dir}")
        return model, scaler, features
        
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return None, None, None

# ============================================================================
# DATA PROCESSING UTILITIES
# ============================================================================

def extract_packet_features(packet):
    """Extract features from network packet for analysis"""
    features = {
        'duration': 0,
        'src_bytes': 0,
        'dst_bytes': 0,
        'count': 1,
        'srv_count': 1,
        'serror_rate': 0,
        'srv_serror_rate': 0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0
    }
    
    try:
        if hasattr(packet, 'length'):
            features['src_bytes'] = int(packet.length)
        
        if hasattr(packet, 'tcp'):
            features['dst_bytes'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
        elif hasattr(packet, 'udp'):
            features['dst_bytes'] = int(packet.udp.length) if hasattr(packet.udp, 'length') else 0
            
    except Exception as e:
        logger.debug(f"Error extracting features: {e}")
    
    return features

def get_protocol(packet):
    """Extract protocol from packet"""
    if hasattr(packet, 'tcp'):
        return 'TCP'
    elif hasattr(packet, 'udp'):
        return 'UDP'
    elif hasattr(packet, 'icmp'):
        return 'ICMP'
    elif hasattr(packet, 'http'):
        return 'HTTP'
    elif hasattr(packet, 'dns'):
        return 'DNS'
    else:
        return 'Other'

def get_ip_addresses(packet):
    """Extract source and destination IP addresses"""
    src_ip = 'Unknown'
    dst_ip = 'Unknown'
    
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
    except:
        pass
    
    return src_ip, dst_ip

# ============================================================================
# REPORT GENERATION
# ============================================================================

def generate_summary_report(alerts, time_range='24h'):
    """Generate summary report of network activity"""
    report_file = os.path.join(PATHS['reports_dir'], 
                               f'security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    
    with open(report_file, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("AI NETWORK SECURITY GUARD - SUMMARY REPORT\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Time Range: {time_range}\n\n")
        
        # Alert statistics
        f.write("ALERT STATISTICS:\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total Alerts: {len(alerts)}\n")
        
        # Severity breakdown
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            f.write(f"  {severity}: {count}\n")
        
        f.write("\n")
        
        # Top source IPs
        f.write("TOP SOURCE IPs:\n")
        f.write("-" * 70 + "\n")
        src_ips = {}
        for alert in alerts:
            src_ip = alert.get('src_ip', 'Unknown')
            src_ips[src_ip] = src_ips.get(src_ip, 0) + 1
        
        for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
            f.write(f"  {ip}: {count} alerts\n")
        
        f.write("\n")
        
        # Recent critical alerts
        f.write("RECENT CRITICAL ALERTS:\n")
        f.write("-" * 70 + "\n")
        critical = [a for a in alerts if a.get('severity') == 'CRITICAL']
        for alert in critical[-10:]:
            f.write(f"  {alert.get('timestamp')} - {alert.get('protocol')} "
                   f"{alert.get('src_ip')} → {alert.get('dst_ip')}\n")
        
        f.write("\n" + "=" * 70 + "\n")
    
    logger.info(f"📊 Report generated: {report_file}")
    return report_file

# ============================================================================
# SYSTEM UTILITIES
# ============================================================================

def check_dependencies():
    """Check if all required dependencies are installed"""
    required = ['pandas', 'numpy', 'sklearn', 'pyshark', 'streamlit', 'plotly']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        logger.warning(f"⚠️  Missing packages: {', '.join(missing)}")
        logger.info("Install with: pip install " + " ".join(missing))
        return False
    
    logger.info("✅ All dependencies installed")
    return True

def get_network_interfaces():
    """Get list of available network interfaces"""
    try:
        import pyshark
        interfaces = pyshark.get_interfaces()
        return interfaces
    except:
        logger.warning("Could not retrieve network interfaces")
        return []

# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

__all__ = [
    'logger',
    'setup_logger',
    'log_alert',
    'read_alert_logs',
    'send_email_alert',
    'send_slack_alert',
    'play_alert_sound',
    'save_model',
    'load_model',
    'extract_packet_features',
    'get_protocol',
    'get_ip_addresses',
    'generate_summary_report',
    'check_dependencies',
    'get_network_interfaces',
]
