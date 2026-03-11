"""
AI Network Security Guard - Firewall Manager
Automatic blocking of malicious IPs with cross-platform support
"""

import os
import json
import subprocess
import platform
from datetime import datetime, timedelta
from threading import Lock
from collections import defaultdict

try:
    from config_enhanced import FIREWALL_CONFIG, PATHS
    from utils_enhanced import logger
except ImportError:
    from config import FIREWALL_CONFIG, PATHS
    from utils import logger


class FirewallManager:
    """
    Manages automatic blocking of malicious IPs across different platforms
    """
    
    def __init__(self):
        """Initialize Firewall Manager"""
        self.blocked_ips = {}  # {ip: {'timestamp': dt, 'reason': str, 'severity': str}}
        self.block_history = []
        self.block_lock = Lock()
        self.system = platform.system()
        
        # Load existing blocks
        self._load_blocked_ips()
        
        # Statistics
        self.stats = {
            'total_blocks': 0,
            'active_blocks': 0,
            'expired_blocks': 0,
            'whitelist_skips': 0,
        }
        
        logger.info(f"🔥 Firewall Manager initialized on {self.system}")
        logger.info(f"   Auto-block: {'✅ Enabled' if FIREWALL_CONFIG['auto_block_enabled'] else '❌ Disabled'}")
    
    def should_block_ip(self, ip_address, severity, alert_count=1):
        """
        Determine if an IP should be blocked
        
        Args:
            ip_address: IP to check
            severity: Alert severity level
            alert_count: Number of alerts from this IP
            
        Returns:
            Tuple (should_block: bool, reason: str)
        """
        # Check if auto-block is enabled
        if not FIREWALL_CONFIG['auto_block_enabled']:
            return False, "Auto-block disabled"
        
        # Check whitelist
        if ip_address in FIREWALL_CONFIG['whitelist_ips']:
            self.stats['whitelist_skips'] += 1
            return False, f"IP {ip_address} is whitelisted"
        
        # Check if already blocked
        if ip_address in self.blocked_ips:
            return False, f"IP {ip_address} already blocked"
        
        # Check severity-based blocking
        if severity in FIREWALL_CONFIG['block_on_severity']:
            if alert_count >= FIREWALL_CONFIG['block_threshold_count']:
                return True, f"Alert threshold exceeded ({alert_count} alerts, severity: {severity})"
        
        # Check for permanent block on critical
        if severity == 'CRITICAL' and FIREWALL_CONFIG['permanent_block_on_critical']:
            return True, f"Critical severity - immediate block"
        
        return False, "Threshold not met"
    
    def block_ip(self, ip_address, severity, reason="Malicious activity detected"):
        """
        Block an IP address using system firewall
        
        Args:
            ip_address: IP address to block
            severity: Severity level
            reason: Reason for blocking
            
        Returns:
            True if successfully blocked, False otherwise
        """
        with self.block_lock:
            # Check if already blocked
            if ip_address in self.blocked_ips:
                logger.debug(f"IP {ip_address} already blocked")
                return False
            
            # Determine block duration
            if FIREWALL_CONFIG['permanent_block_on_critical'] and severity == 'CRITICAL':
                duration_minutes = 0  # Permanent
            else:
                duration_minutes = FIREWALL_CONFIG['block_duration_minutes']
            
            # Execute platform-specific blocking
            success = False
            if self.system == 'Linux':
                success = self._block_ip_linux(ip_address)
            elif self.system == 'Windows':
                success = self._block_ip_windows(ip_address)
            elif self.system == 'Darwin':  # macOS
                success = self._block_ip_macos(ip_address)
            else:
                logger.error(f"Unsupported platform: {self.system}")
                return False
            
            if success:
                # Record the block
                block_data = {
                    'timestamp': datetime.now(),
                    'severity': severity,
                    'reason': reason,
                    'duration_minutes': duration_minutes,
                    'expires_at': None if duration_minutes == 0 else datetime.now() + timedelta(minutes=duration_minutes),
                    'system': self.system,
                }
                
                self.blocked_ips[ip_address] = block_data
                self.block_history.append({
                    'ip': ip_address,
                    **block_data,
                    'timestamp': block_data['timestamp'].isoformat()
                })
                
                # Update statistics
                self.stats['total_blocks'] += 1
                self.stats['active_blocks'] = len(self.blocked_ips)
                
                # Save to disk
                self._save_blocked_ips()
                
                # Log the block
                self._log_block_action(ip_address, block_data)
                
                duration_str = "permanently" if duration_minutes == 0 else f"for {duration_minutes} minutes"
                logger.warning(f"🚫 BLOCKED IP: {ip_address} {duration_str} | Reason: {reason}")
                
                return True
            else:
                logger.error(f"Failed to block IP: {ip_address}")
                return False
    
    def _block_ip_linux(self, ip_address):
        """Block IP using iptables (Linux)"""
        try:
            # Add iptables rule to drop packets from this IP
            cmd = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.debug(f"iptables rule added for {ip_address}")
                return True
            else:
                logger.error(f"iptables error: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error blocking IP on Linux: {e}")
            return False
    
    def _block_ip_windows(self, ip_address):
        """Block IP using Windows Firewall"""
        try:
            # Create Windows Firewall rule
            rule_name = f"AI_Security_Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 or "Ok." in result.stdout:
                logger.debug(f"Windows Firewall rule added for {ip_address}")
                return True
            else:
                logger.error(f"Windows Firewall error: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error blocking IP on Windows: {e}")
            return False
    
    def _block_ip_macos(self, ip_address):
        """Block IP using pfctl (macOS)"""
        try:
            # Add to pf firewall table
            cmd = f"echo 'block drop from {ip_address} to any' | sudo pfctl -f -"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.debug(f"pfctl rule added for {ip_address}")
                return True
            else:
                logger.error(f"pfctl error: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error blocking IP on macOS: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """
        Remove block from an IP address
        
        Args:
            ip_address: IP to unblock
            
        Returns:
            True if successfully unblocked
        """
        with self.block_lock:
            if ip_address not in self.blocked_ips:
                logger.warning(f"IP {ip_address} not in blocked list")
                return False
            
            # Execute platform-specific unblocking
            success = False
            if self.system == 'Linux':
                success = self._unblock_ip_linux(ip_address)
            elif self.system == 'Windows':
                success = self._unblock_ip_windows(ip_address)
            elif self.system == 'Darwin':
                success = self._unblock_ip_macos(ip_address)
            
            if success:
                # Remove from blocked list
                del self.blocked_ips[ip_address]
                self.stats['active_blocks'] = len(self.blocked_ips)
                self.stats['expired_blocks'] += 1
                
                # Save to disk
                self._save_blocked_ips()
                
                logger.info(f"✅ UNBLOCKED IP: {ip_address}")
                return True
            else:
                logger.error(f"Failed to unblock IP: {ip_address}")
                return False
    
    def _unblock_ip_linux(self, ip_address):
        """Unblock IP using iptables (Linux)"""
        try:
            cmd = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error unblocking IP on Linux: {e}")
            return False
    
    def _unblock_ip_windows(self, ip_address):
        """Unblock IP using Windows Firewall"""
        try:
            rule_name = f"AI_Security_Block_{ip_address.replace('.', '_')}"
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0 or "Ok." in result.stdout
        except Exception as e:
            logger.error(f"Error unblocking IP on Windows: {e}")
            return False
    
    def _unblock_ip_macos(self, ip_address):
        """Unblock IP using pfctl (macOS)"""
        try:
            # Remove from pf table (simplified - in production, use proper pf table management)
            cmd = f"sudo pfctl -t blocklist -T delete {ip_address}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error unblocking IP on macOS: {e}")
            return False
    
    def check_and_unblock_expired(self):
        """Check for and unblock expired IP blocks"""
        now = datetime.now()
        expired_ips = []
        
        with self.block_lock:
            for ip, data in self.blocked_ips.items():
                if data['expires_at'] is not None and now > data['expires_at']:
                    expired_ips.append(ip)
        
        # Unblock expired IPs
        for ip in expired_ips:
            self.unblock_ip(ip)
            logger.info(f"⏰ Block expired for {ip}")
    
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        with self.block_lock:
            return list(self.blocked_ips.keys())
    
    def get_block_info(self, ip_address):
        """Get detailed information about a blocked IP"""
        with self.block_lock:
            return self.blocked_ips.get(ip_address, None)
    
    def get_statistics(self):
        """Get firewall statistics"""
        return self.stats.copy()
    
    def _save_blocked_ips(self):
        """Save blocked IPs to disk"""
        try:
            filepath = FIREWALL_CONFIG['blocked_ips_file']
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Convert datetime objects to strings for JSON serialization
            data = {
                ip: {
                    'timestamp': block['timestamp'].isoformat(),
                    'severity': block['severity'],
                    'reason': block['reason'],
                    'duration_minutes': block['duration_minutes'],
                    'expires_at': block['expires_at'].isoformat() if block['expires_at'] else None,
                    'system': block['system'],
                }
                for ip, block in self.blocked_ips.items()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Blocked IPs saved to {filepath}")
        except Exception as e:
            logger.error(f"Error saving blocked IPs: {e}")
    
    def _load_blocked_ips(self):
        """Load blocked IPs from disk"""
        try:
            filepath = FIREWALL_CONFIG['blocked_ips_file']
            
            if not os.path.exists(filepath):
                return
            
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Convert string timestamps back to datetime objects
            for ip, block in data.items():
                self.blocked_ips[ip] = {
                    'timestamp': datetime.fromisoformat(block['timestamp']),
                    'severity': block['severity'],
                    'reason': block['reason'],
                    'duration_minutes': block['duration_minutes'],
                    'expires_at': datetime.fromisoformat(block['expires_at']) if block['expires_at'] else None,
                    'system': block['system'],
                }
            
            self.stats['active_blocks'] = len(self.blocked_ips)
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from disk")
            
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
    
    def _log_block_action(self, ip_address, block_data):
        """Log blocking action to file"""
        if not FIREWALL_CONFIG['log_blocked_ips']:
            return
        
        try:
            log_file = FIREWALL_CONFIG['block_log_file']
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            
            log_entry = {
                'timestamp': block_data['timestamp'].isoformat(),
                'ip': ip_address,
                'severity': block_data['severity'],
                'reason': block_data['reason'],
                'duration_minutes': block_data['duration_minutes'],
                'system': block_data['system'],
            }
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            logger.error(f"Error logging block action: {e}")
    
    def generate_block_report(self):
        """Generate a report of all blocking activity"""
        report = []
        report.append("=" * 70)
        report.append("FIREWALL BLOCKING REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Platform: {self.system}")
        report.append("")
        
        # Statistics
        report.append("STATISTICS:")
        report.append(f"  Total Blocks: {self.stats['total_blocks']}")
        report.append(f"  Active Blocks: {self.stats['active_blocks']}")
        report.append(f"  Expired Blocks: {self.stats['expired_blocks']}")
        report.append(f"  Whitelist Skips: {self.stats['whitelist_skips']}")
        report.append("")
        
        # Currently blocked IPs
        if self.blocked_ips:
            report.append("CURRENTLY BLOCKED IPs:")
            report.append("-" * 70)
            for ip, data in sorted(self.blocked_ips.items()):
                expires = "Permanent" if data['expires_at'] is None else data['expires_at'].strftime('%Y-%m-%d %H:%M:%S')
                report.append(f"  {ip}")
                report.append(f"    Severity: {data['severity']}")
                report.append(f"    Reason: {data['reason']}")
                report.append(f"    Blocked: {data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                report.append(f"    Expires: {expires}")
                report.append("")
        else:
            report.append("No IPs currently blocked")
        
        report.append("=" * 70)
        return "\n".join(report)


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'FirewallManager',
]
