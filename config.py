"""
Simple Configuration for AI Network Security Guard
"""

NETWORK_CONFIG = {
    'default_interface': 'WiFi',  # Change to your interface
}

FIREWALL_CONFIG = {
    'auto_block_enabled': False,  # Disabled for simplicity
    'whitelist_ips': ['127.0.0.1', '192.168.0.106', '192.168.0.1'],
}

NOTIFICATION_CONFIG = {
    'telegram_enabled': False,  # Disabled for simplicity
}

def get_severity_from_score(anomaly_score):
    if anomaly_score < -0.15: # Was -0.5
        return 'CRITICAL'
    elif anomaly_score < -0.1:  # Was -0.3
        return 'HIGH'
    elif anomaly_score < -0.05: # Was -0.15
        return 'MEDIUM'
    else:
        return 'LOW'
