"""
AI Network Security Guard - Enhanced Configuration
Centralized config for AI monitoring, auto-block, notifications, and forensics
"""

import os

# ============================
# SYSTEM & TSHARK PATH
# ============================
TSHARK_PATH = r"E:\Wireshark\tshark.exe"

# ============================
# NETWORK MONITOR CONFIGURATION
# ============================
NETWORK_CONFIG = {
    'default_interface': 'WiFi',
    'packet_count': 0,  # 0 = infinite
    'capture_timeout': 10,
    'display_filter': None,
    'bpf_filter': None,
    'stats_update_interval': 10,
}

# ============================
# MODEL CONFIGURATION
# ============================
MODEL_CONFIG = {
    'contamination': 0.01,
    'n_estimators': 100,
    'max_samples': 'auto',
    'random_state': 42,
    'verbose': 0,  # <--- Change this to 0 to stop the "Done 100 tasks" messages
    'features': [ ... ],
    # ...
}

# ============================
# DATASET CONFIGURATION
# ============================
DATASET_CONFIG = {
    'train_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
    'test_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt',
    'train_file': 'data/KDDTrain.txt',
    'test_file': 'data/KDDTest.txt',
    'columns': [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
    ],
}

# ============================
# ANOMALY DETECTION THRESHOLDS
# ============================
DETECTION_CONFIG = {
    'severity_thresholds': {
        'CRITICAL': -0.5,
        'HIGH': -0.3,
        'MEDIUM': -0.1,
        'LOW': 0.0,
    },
    'max_alerts_stored': 1000,
    'alert_cooldown': 1.0,
    'log_all_packets': False,
    'log_anomalies_only': True,
    'log_file': 'security_alerts.log',
}

# ============================
# FIREWALL / AUTO-BLOCK CONFIGURATION
# ============================
FIREWALL_CONFIG = {
    'auto_block_enabled': True,
    'block_on_severity': ['CRITICAL', 'HIGH'],
    'block_threshold_count': 3,
    'block_threshold_time_minutes': 5,
    'block_duration_minutes': 60,
    'permanent_block_on_critical': True,
    'whitelist_ips': ['127.0.0.1', '::1', 'localhost', '192.168.0.106', '192.168.0.1'],
    'use_iptables': True,
    'use_windows_firewall': True,
    'log_blocked_ips': True,
    'block_entire_subnet': False,
    'notify_on_block': True,
    'blocked_ips_file': 'data/blocked_ips.json',
    'block_log_file': 'firewall_blocks.log',
}

# ============================
# DASHBOARD CONFIGURATION
# ============================
DASHBOARD_CONFIG = {
    'page_title': 'AI Network Security Guard',
    'page_icon': '🛡️',
    'layout': 'wide',
    'auto_refresh_interval': 2,
    'max_alerts_display': 50,
    'chart_height': 300,
    'show_protocol_chart': True,
    'show_severity_chart': True,
    'show_timeline_chart': True,
    'show_ip_analysis': True,
    'show_firewall_status': True,
    'show_forensic_data': True,
    'colors': {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff9933',
        'MEDIUM': '#ffdd44',
        'LOW': '#44ff44',
        'normal': '#4444ff',
        'blocked': '#ff0000',
    },
}

# ============================
# NOTIFICATIONS CONFIGURATION
# ============================
NOTIFICATION_CONFIG = {
    'email_enabled': False,
    'email_smtp_server': 'smtp.gmail.com',
    'email_smtp_port': 587,
    'email_sender': 'your_email@gmail.com',
    'email_password': 'YOUR_APP_PASSWORD',
    'email_recipients': ['admin@company.com'],
    'email_on_severity': ['CRITICAL', 'HIGH'],

    'telegram_enabled': False,
    'telegram_bot_token': 'YOUR_BOT_TOKEN',
    'telegram_chat_ids': ['YOUR_CHAT_ID'],
    'telegram_on_severity': ['CRITICAL', 'HIGH', 'MEDIUM'],
    'telegram_send_graphs': True,
    'telegram_instant_alerts': True,

    'slack_enabled': False,
    'slack_webhook_url': '',
    'slack_on_severity': ['CRITICAL', 'HIGH'],

    'sms_enabled': False,
    'twilio_account_sid': '',
    'twilio_auth_token': '',
    'twilio_phone_from': '',
    'twilio_phone_to': [],
    'sms_on_severity': ['CRITICAL'],

    'sound_enabled': True,
    'sound_on_severity': ['CRITICAL', 'HIGH'],
    'max_notifications_per_hour': 50,
    'notification_cooldown_seconds': 30,
}

# ============================
# FORENSIC CONFIGURATION
# ============================
FORENSIC_CONFIG = {
    'forensic_enabled': True,
    'capture_full_packets': True,
    'pcap_storage_enabled': True,
    'max_pcap_size_mb': 500,
    'detailed_packet_logging': True,
    'log_connection_metadata': True,
    'log_payload_samples': True,
    'payload_sample_size': 64,
    'auto_generate_reports': True,
    'report_interval_hours': 24,
    'report_format': 'both',
    'include_graphs': True,
    'pattern_analysis_enabled': True,
    'ml_threat_classification': True,
    'geo_ip_lookup': True,
    'forensic_data_retention_days': 90,
    'compress_old_logs': True,
    'forensic_dir': 'forensics',
    'pcap_dir': 'forensics/pcaps',
    'reports_dir': 'forensics/reports',
    'evidence_dir': 'forensics/evidence',
}

# ============================
# LOGGING CONFIGURATION
# ============================
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'log_file': 'network_guard.log',
    'log_max_bytes': 10 * 1024 * 1024,
    'log_backup_count': 5,
    'structured_logging': True,
}

# ============================
# PERFORMANCE CONFIGURATION
# ============================
PERFORMANCE_CONFIG = {
    'use_multithreading': True,
    'worker_threads': 4,
    'batch_size': 10,
    'batch_timeout': 1.0,
    'max_memory_mb': 512,
    'clear_old_data_interval': 300,
    'use_database': False,
    'database_type': 'sqlite',
    'database_path': 'data/security.db',
}

# ============================
# SYSTEM PATHS
# ============================
PATHS = {
    'data_dir': 'data',
    'models_dir': 'models',
    'logs_dir': 'logs',
    'reports_dir': 'reports',
    'cache_dir': 'cache',
    'forensics_dir': 'forensics',
    'pcaps_dir': 'forensics/pcaps',
    'evidence_dir': 'forensics/evidence',
}

# Ensure all directories exist
for path in PATHS.values():
    os.makedirs(path, exist_ok=True)

# ============================
# HELPER FUNCTIONS
# ============================
def get_severity_from_score(score):
    thresholds = DETECTION_CONFIG['severity_thresholds']
    if score < thresholds['CRITICAL']:
        return 'CRITICAL'
    elif score < thresholds['HIGH']:
        return 'HIGH'
    elif score < thresholds['MEDIUM']:
        return 'MEDIUM'
    return 'LOW'

def should_send_notification(severity):
    if NOTIFICATION_CONFIG.get('email_enabled') and severity in NOTIFICATION_CONFIG.get('email_on_severity', []):
        return True
    if NOTIFICATION_CONFIG.get('telegram_enabled') and severity in NOTIFICATION_CONFIG.get('telegram_on_severity', []):
        return True
    if NOTIFICATION_CONFIG.get('slack_enabled') and severity in NOTIFICATION_CONFIG.get('slack_on_severity', []):
        return True
    if NOTIFICATION_CONFIG.get('sms_enabled') and severity in NOTIFICATION_CONFIG.get('sms_on_severity', []):
        return True
    return False

def should_auto_block(severity, ip_address):
    if not FIREWALL_CONFIG.get('auto_block_enabled', False):
        return False
    if ip_address in FIREWALL_CONFIG.get('whitelist_ips', []):
        return False
    if severity in FIREWALL_CONFIG.get('block_on_severity', []):
        return True
    return False

# ============================
# EXPORT CONFIGS
# ============================
__all__ = [
    'TSHARK_PATH', 'MODEL_CONFIG', 'DATASET_CONFIG', 'NETWORK_CONFIG', 'DETECTION_CONFIG',
    'FIREWALL_CONFIG', 'DASHBOARD_CONFIG', 'NOTIFICATION_CONFIG', 'FORENSIC_CONFIG',
    'LOGGING_CONFIG', 'PERFORMANCE_CONFIG', 'PATHS',
    'get_severity_from_score', 'should_send_notification', 'should_auto_block'
]