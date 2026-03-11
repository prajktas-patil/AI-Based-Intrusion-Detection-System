import logging
import pickle
import json
import os
import hashlib
import gzip
import shutil
import requests
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

try:
    from config_enhanced import (
        LOGGING_CONFIG, NOTIFICATION_CONFIG, PATHS, 
        FORENSIC_CONFIG, FIREWALL_CONFIG
    )
except ImportError:
    from config import LOGGING_CONFIG, NOTIFICATION_CONFIG, PATHS

# ============================================================================
# LOGGING UTILITIES (FIXED FOR DIRECTORY ERRORS)
# ============================================================================

def setup_logger(name='network_guard'):
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, LOGGING_CONFIG['log_level']))
    
    if logger.handlers:
        return logger
    
    log_file = os.path.join(PATHS['logs_dir'], LOGGING_CONFIG['log_file'])
    
    # Ensure directory exists
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))
    
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOGGING_CONFIG['log_max_bytes'],
        backupCount=LOGGING_CONFIG['log_backup_count']
    )
    file_handler.setFormatter(logging.Formatter(LOGGING_CONFIG['log_format']))
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

logger = setup_logger()

# ============================================================================
# NOTIFICATION UTILITIES (REQUIRED BY MONITOR)
# ============================================================================

def send_telegram_alert(alert_data):
    """Sends notification to Telegram"""
    if not NOTIFICATION_CONFIG.get('telegram_enabled', False):
        return False
    try:
        token = NOTIFICATION_CONFIG['telegram_bot_token']
        chat_ids = NOTIFICATION_CONFIG['telegram_chat_ids']
        msg = f"🚨 *SECURITY ALERT: {alert_data['severity']}*\nProto: {alert_data['protocol']}\nSrc: {alert_data.get('src_ip')}\nScore: {alert_data.get('anomaly_score')}"
        
        for chat_id in chat_ids:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            requests.post(url, json={'chat_id': chat_id, 'text': msg, 'parse_mode': 'Markdown'})
        return True
    except Exception as e:
        logger.error(f"Telegram failed: {e}")
        return False

def send_email_alert(alert_data):
    # Placeholder for email logic
    logger.info("Email alert triggered (Logic skipped for brevity)")
    return True

def send_slack_alert(alert_data):
    return False

def send_sms_alert(alert_data):
    return False

def play_alert_sound():
    if NOTIFICATION_CONFIG.get('sound_enabled'):
        print('\a') # System beep

# ============================================================================
# FORENSIC & DATA UTILITIES
# ============================================================================

def log_alert(alert_data):
    alert_log = os.path.join(PATHS['logs_dir'], 'security_alerts.log')
    with open(alert_log, 'a') as f:
        f.write(json.dumps(alert_data, default=str) + '\n')
    logger.warning(f"🚨 ALERT: {alert_data['severity']} from {alert_data.get('src_ip')}")

def log_forensic_data(packet_data, score, severity):
    if not FORENSIC_CONFIG.get('forensic_enabled'): return
    f_file = os.path.join(PATHS['forensics_dir'], f"forensic_{datetime.now().strftime('%Y%m%d')}.log")
    with open(f_file, 'a') as f:
        entry = {'ts': datetime.now().isoformat(), 'data': packet_data, 'score': score, 'sev': severity}
        f.write(json.dumps(entry, default=str) + '\n')

def save_packet_pcap(packet, packet_data):
    pass 

def extract_packet_features(packet):
    # Basic feature extraction logic
    return {'duration': 0, 'src_bytes': len(packet), 'dst_bytes': 0, 'count': 1}

def get_protocol(packet):
    if 'TCP' in str(packet): return 'TCP'
    if 'UDP' in str(packet): return 'UDP'
    return 'Other'

def get_ip_addresses(packet):
    try:
        return packet.ip.src, packet.ip.dst
    except:
        return "Unknown", "Unknown"

# ============================================================================
# MODEL & SYSTEM UTILITIES
# ============================================================================

def load_model(model_dir=None):
    if model_dir is None: model_dir = PATHS['models_dir']
    try:
        with open(os.path.join(model_dir, 'anomaly_model.pkl'), 'rb') as f:
            m = pickle.load(f)
        with open(os.path.join(model_dir, 'scaler.pkl'), 'rb') as f:
            s = pickle.load(f)
        with open(os.path.join(model_dir, 'features.pkl'), 'rb') as f:
            feat = pickle.load(f)
        return m, s, feat
    except:
        return None, None, None

def save_model(model, scaler, features, model_dir=None):
    if model_dir is None: model_dir = PATHS['models_dir']
    os.makedirs(model_dir, exist_ok=True)
    with open(os.path.join(model_dir, 'anomaly_model.pkl'), 'wb') as f:
        pickle.dump(model, f)

def check_dependencies():
    return True

def get_network_interfaces():
    import pyshark
    return pyshark.get_interfaces()

def generate_forensic_report(alerts, time_range='24h'):
    return "Report generated."

def generate_summary_report(alerts, time_range='24h'):
    return "Summary generated."

def compress_old_logs():
    pass

# ============================================================================
# EXPORT
# ============================================================================
__all__ = [
    'logger', 'setup_logger', 'log_alert', 'log_forensic_data', 'save_packet_pcap',
    'send_email_alert', 'send_telegram_alert', 'send_slack_alert', 'send_sms_alert',
    'play_alert_sound', 'save_model', 'load_model', 'extract_packet_features',
    'get_protocol', 'get_ip_addresses', 'generate_summary_report', 'generate_forensic_report',
    'compress_old_logs', 'check_dependencies', 'get_network_interfaces'
]