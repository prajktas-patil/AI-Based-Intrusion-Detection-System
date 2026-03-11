"""
AI Network Security Guard - Configuration File
Centralized configuration for all components
"""

import os

# ============================================================================
# MODEL CONFIGURATION
# ============================================================================

MODEL_CONFIG = {
    # Isolation Forest Parameters
    'contamination': 0.01,  # Expected percentage of anomalies (1%)
    'n_estimators': 100,    # Number of trees in the forest
    'max_samples': 'auto',  # Samples per tree
    'random_state': 42,     # For reproducibility
    'verbose': 1,           # Training verbosity
    
    # Feature Selection
    'features': [
        'duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate'
    ],
    
    # File paths
    'model_path': 'anomaly_model.pkl',
    'scaler_path': 'scaler.pkl',
    'features_path': 'features.pkl',
}

# ============================================================================
# DATASET CONFIGURATION
# ============================================================================

DATASET_CONFIG = {
    # NSL-KDD Dataset URLs
    'train_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt',
    'test_url': 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt',
    
    # Local file paths
    'train_file': 'KDDTrain.txt',
    'test_file': 'KDDTest.txt',
    
    # Column names
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

# ============================================================================
# NETWORK MONITORING CONFIGURATION
# ============================================================================

NETWORK_CONFIG = {
    # Network Interface
    'default_interface': 'Wi-Fi',  # Change based on your system
    
    # Packet Capture Settings
    'packet_count': 100,           # Number of packets to capture (0 = infinite)
    'capture_timeout': 10,         # Timeout in seconds
    'display_filter': None,        # PyShark display filter (None = all packets)
    'bpf_filter': None,            # Berkeley Packet Filter (None = all packets)
    
    # Common BPF Filters (uncomment to use):
    # 'bpf_filter': 'port 80 or port 443',           # HTTP/HTTPS only
    # 'bpf_filter': 'tcp',                            # TCP only
    # 'bpf_filter': 'not port 22',                    # Exclude SSH
    # 'bpf_filter': 'host 192.168.1.1',              # Specific host
    
    # Statistics Update Frequency
    'stats_update_interval': 10,   # Print stats every N packets
}

# ============================================================================
# ANOMALY DETECTION THRESHOLDS
# ============================================================================

DETECTION_CONFIG = {
    # Severity Thresholds (based on anomaly score)
    'severity_thresholds': {
        'CRITICAL': -0.5,   # Score < -0.5
        'HIGH': -0.3,       # Score < -0.3
        'MEDIUM': -0.1,     # Score < -0.1
        'LOW': 0.0,         # Score < 0.0
    },
    
    # Alert Settings
    'max_alerts_stored': 1000,      # Maximum alerts to keep in memory
    'alert_cooldown': 1.0,          # Seconds between duplicate alerts
    
    # Logging
    'log_all_packets': False,       # Log every packet (creates large files)
    'log_anomalies_only': True,     # Only log detected anomalies
    'log_file': 'security_alerts.log',
}

# ============================================================================
# DASHBOARD CONFIGURATION
# ============================================================================

DASHBOARD_CONFIG = {
    # Streamlit Settings
    'page_title': 'AI Network Security Guard',
    'page_icon': '🛡️',
    'layout': 'wide',
    
    # Update Intervals
    'auto_refresh_interval': 2,     # Seconds between dashboard refreshes
    'max_alerts_display': 50,       # Maximum alerts to show in table
    
    # Visualization Settings
    'chart_height': 300,
    'show_protocol_chart': True,
    'show_severity_chart': True,
    'show_timeline_chart': True,
    'show_ip_analysis': True,
    
    # Color Scheme
    'colors': {
        'CRITICAL': '#ff4444',
        'HIGH': '#ff9933',
        'MEDIUM': '#ffdd44',
        'LOW': '#44ff44',
        'normal': '#4444ff',
    },
}

# ============================================================================
# ALERT NOTIFICATION CONFIGURATION
# ============================================================================

NOTIFICATION_CONFIG = {
    # Email Alerts (Set to True to enable)
    'email_enabled': False,
    'email_smtp_server': 'smtp.gmail.com',
    'email_smtp_port': 587,
    'email_sender': 'your_email@gmail.com',
    'email_password': 'your_app_password',
    'email_recipients': ['admin@company.com'],
    'email_on_severity': ['CRITICAL', 'HIGH'],  # Only send email for these
    
    # Slack Alerts (Set to True to enable)
    'slack_enabled': False,
    'slack_webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
    'slack_on_severity': ['CRITICAL', 'HIGH'],
    
    # Sound Alerts
    'sound_enabled': True,
    'sound_on_severity': ['CRITICAL', 'HIGH'],
}

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOGGING_CONFIG = {
    'log_level': 'INFO',            # DEBUG, INFO, WARNING, ERROR, CRITICAL
    'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'log_file': 'network_guard.log',
    'log_max_bytes': 10 * 1024 * 1024,  # 10 MB
    'log_backup_count': 5,          # Keep 5 backup files
}

# ============================================================================
# PERFORMANCE CONFIGURATION
# ============================================================================

PERFORMANCE_CONFIG = {
    # Threading
    'use_multithreading': True,
    'worker_threads': 4,
    
    # Batch Processing
    'batch_size': 10,               # Process packets in batches
    'batch_timeout': 1.0,           # Seconds to wait for batch
    
    # Memory Management
    'max_memory_mb': 512,           # Maximum memory usage
    'clear_old_data_interval': 300, # Clear old data every N seconds
}

# ============================================================================
# SYSTEM PATHS
# ============================================================================

PATHS = {
    'data_dir': 'data',
    'models_dir': 'models',
    'logs_dir': 'logs',
    'reports_dir': 'reports',
    'cache_dir': 'cache',
}

# Create directories if they don't exist
for path in PATHS.values():
    os.makedirs(path, exist_ok=True)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_severity_color(severity):
    """Get color for severity level"""
    return DASHBOARD_CONFIG['colors'].get(severity, '#888888')

def get_severity_from_score(score):
    """Determine severity level from anomaly score"""
    thresholds = DETECTION_CONFIG['severity_thresholds']
    
    if score < thresholds['CRITICAL']:
        return 'CRITICAL'
    elif score < thresholds['HIGH']:
        return 'HIGH'
    elif score < thresholds['MEDIUM']:
        return 'MEDIUM'
    else:
        return 'LOW'

def should_send_notification(severity):
    """Check if notification should be sent for this severity"""
    if NOTIFICATION_CONFIG['email_enabled']:
        if severity in NOTIFICATION_CONFIG['email_on_severity']:
            return True
    if NOTIFICATION_CONFIG['slack_enabled']:
        if severity in NOTIFICATION_CONFIG['slack_on_severity']:
            return True
    return False

# ============================================================================
# EXPORT ALL CONFIGS
# ============================================================================

__all__ = [
    'MODEL_CONFIG',
    'DATASET_CONFIG',
    'NETWORK_CONFIG',
    'DETECTION_CONFIG',
    'DASHBOARD_CONFIG',
    'NOTIFICATION_CONFIG',
    'LOGGING_CONFIG',
    'PERFORMANCE_CONFIG',
    'PATHS',
    'get_severity_color',
    'get_severity_from_score',
    'should_send_notification',
]
