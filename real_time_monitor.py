"""
AI Network Security Guard - Real-Time Attack Detection (Windows Compatible)
Monitors live traffic and detects attacks instantly with AI, firewall, and alerts.
"""
import warnings
warnings.filterwarnings("ignore")
import os
os.environ['PYTHONWARNINGS'] = 'ignore'
import sys
import logging
import asyncio
from datetime import datetime
from collections import defaultdict
import pickle
import numpy as np
import pyshark

# ============================
# UTF-8 Logging Setup
# ============================
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
console_handler.setLevel(logging.INFO)

logger = logging.getLogger()
logger.handlers = []
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

# Log to file as UTF-8
file_handler = logging.FileHandler('network_guard.log', encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# ============================
# Imports from config and utils
# ============================
try:
    from config_enhanced import NETWORK_CONFIG, FIREWALL_CONFIG, NOTIFICATION_CONFIG, get_severity_from_score, TSHARK_PATH
    from utils_enhanced import send_telegram_alert, send_email_alert, log_forensic_data
    from alert_manager_enhanced import EnhancedAlertManager
    from firewall_manager import FirewallManager
except ImportError as e:
    logger.error(f"Import failed: {e}")
    exit(1)

# ============================
# Real-Time Attack Detector
# ============================
class RealTimeAttackDetector:
    def __init__(self, interface='WiFi'):
        self.interface = interface
        self.packet_count = 0
        self.anomaly_count = 0
        self.start_time = datetime.now()
        self.connection_tracker = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'first_seen': None, 'last_seen': None, 'ports': set(), 'alerts': 0
        })

        # Load AI model
        logger.info("Loading AI model...")
        try:
            with open('anomaly_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            with open('scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
            with open('features.pkl', 'rb') as f:
                self.feature_names = pickle.load(f)
            logger.info("AI model loaded successfully!")
        except FileNotFoundError:
            logger.error("Model files not found! Run: python train_model.py")
            exit(1)

        # Initialize alert manager
        self.alert_manager = EnhancedAlertManager()

        # Initialize firewall
        self.firewall = None
        if FIREWALL_CONFIG.get('auto_block_enabled', False):
            try:
                self.firewall = FirewallManager()
            except Exception as e:
                logger.warning(f"Firewall manager unavailable: {e}")

        logger.info(f"Detector initialized | Interface: {self.interface} | Auto-block: {'ENABLED' if self.firewall else 'DISABLED'} | Telegram alerts: {'ENABLED' if NOTIFICATION_CONFIG.get('telegram_enabled') else 'DISABLED'}")

    # ----------------------------
    # Packet Processing Utilities
    # ----------------------------
    def get_protocol(self, packet):
        if hasattr(packet, 'tcp'): return 'TCP'
        if hasattr(packet, 'udp'): return 'UDP'
        if hasattr(packet, 'icmp'): return 'ICMP'
        if hasattr(packet, 'http'): return 'HTTP'
        if hasattr(packet, 'dns'): return 'DNS'
        return 'Other'

    def get_ip_addresses(self, packet):
        src_ip = dst_ip = 'Unknown'
        try:
            if hasattr(packet, 'ip'):
                src_ip, dst_ip = packet.ip.src, packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                src_ip, dst_ip = packet.ipv6.src, packet.ipv6.dst
        except: pass
        return src_ip, dst_ip

    def extract_features_from_packet(self, packet):
        try:
            protocol = self.get_protocol(packet)
            src_ip, dst_ip = self.get_ip_addresses(packet)
            src_port = int(packet.tcp.srcport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') else 0
            dst_port = int(packet.tcp.dstport) if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'dstport') else 0
            if hasattr(packet, 'udp'):
                src_port = int(packet.udp.srcport) if hasattr(packet.udp, 'srcport') else src_port
                dst_port = int(packet.udp.dstport) if hasattr(packet.udp, 'dstport') else dst_port

            packet_size = int(packet.length) if hasattr(packet, 'length') else 0
            conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            now = datetime.now()
            if self.connection_tracker[conn_key]['first_seen'] is None:
                self.connection_tracker[conn_key]['first_seen'] = now
            self.connection_tracker[conn_key]['last_seen'] = now
            self.connection_tracker[conn_key]['packets'] += 1
            self.connection_tracker[conn_key]['bytes'] += packet_size
            self.connection_tracker[conn_key]['ports'].add(dst_port)
            duration = (now - self.connection_tracker[conn_key]['first_seen']).total_seconds()

            features = {
                'duration': duration,
                'src_bytes': packet_size,
                'dst_bytes': packet_size // 2,
                'count': self.connection_tracker[conn_key]['packets'],
                'srv_count': len(self.connection_tracker[conn_key]['ports']),
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
            }

            packet_data = {
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'src_bytes': packet_size,
                'duration': duration,
                'count': self.connection_tracker[conn_key]['packets'],
                'timestamp': now,
            }
            return features, packet_data
        except:
            return None, None

    def detect_attack(self, features):
        try:
            arr = np.array([[features[k] for k in ['duration','src_bytes','dst_bytes','count','srv_count','serror_rate','srv_serror_rate','same_srv_rate','diff_srv_rate']]])
            arr_scaled = self.scaler.transform(arr)
            score = self.model.score_samples(arr_scaled)[0]
            is_anomaly = self.model.predict(arr_scaled)[0] == -1
            return is_anomaly, score
        except: return False, 0.0

    def detect_attack_patterns(self, src_ip):
        patterns = []
        for key, data in self.connection_tracker.items():
            if key.startswith(src_ip):
                if len(data['ports']) > 10:
                    patterns.append({'type':'PORT_SCAN','description':f'Port scan: {len(data["ports"])} ports','severity':'HIGH'})
                duration = (datetime.now() - data['first_seen']).total_seconds()
                if duration > 0 and (data['packets']/duration) > 100:
                    patterns.append({'type':'DDOS','description':f'High packet rate: {data["packets"]/duration:.0f} pkt/sec','severity':'CRITICAL'})
                break
        return patterns

    def process_packet(self, packet):
        self.packet_count += 1
        features, pdata = self.extract_features_from_packet(packet)
        if features is None or pdata is None: return
        is_anomaly, score = self.detect_attack(features)

        if self.packet_count % 10 == 0:
            runtime = (datetime.now() - self.start_time).total_seconds()
            print(f"Packets: {self.packet_count} | Anomalies: {self.anomaly_count} | Runtime: {runtime:.0f}s", end='\r')

        if is_anomaly:
            self.anomaly_count += 1
            severity = get_severity_from_score(score)
            alert = self.alert_manager.create_alert(pdata, score, severity)
            self.alert_manager.add_alert(alert)
            patterns = self.detect_attack_patterns(pdata['src_ip'])

            print("\n" + "="*80)
            print(f"ATTACK DETECTED! Anomaly #{self.anomaly_count}")
            print(f"Time: {pdata['timestamp'].strftime('%H:%M:%S')} | Severity: {severity} | Score: {score:.4f}")
            print(f"Protocol: {pdata['protocol']} | Source: {pdata['src_ip']}:{pdata['src_port']} -> Destination: {pdata['dst_ip']}:{pdata['dst_port']}")
            if patterns:
                print("Patterns:")
                for p in patterns: print(f"  * {p['type']}: {p['description']}")
            if alert.get('blocked', False):
                print(f"\nIP BLOCKED: {pdata['src_ip']}")
            print("="*80)

    # ----------------------------
    # Start Monitoring
    # ----------------------------
    def start_monitoring(self):
        print("\n" + "="*80)
        print("REAL-TIME ATTACK DETECTION STARTED")
        print("="*80)
        print(f"Interface: {self.interface} | Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("Monitoring live traffic... Press Ctrl+C to stop")
        print("="*80 + "\n")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            capture = pyshark.LiveCapture(interface=self.interface, tshark_path=TSHARK_PATH, eventloop=loop)
            for packet in capture.sniff_continuously():
                self.process_packet(packet)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            self.print_summary()
        except PermissionError:
            logger.error("Permission denied! Run as Administrator (Windows) or sudo (Linux/Mac)")
        except Exception as e:
            logger.error(f"Error: {e}")

    # ----------------------------
    # Summary
    # ----------------------------
    def print_summary(self):
        runtime = (datetime.now() - self.start_time).total_seconds()
        print(f"\nTotal Packets: {self.packet_count} | Anomalies: {self.anomaly_count} | Runtime: {runtime:.0f}s")
        stats = self.alert_manager.get_statistics()
        print(f"Critical: {stats.get('critical',0)} | High: {stats.get('high',0)} | Medium: {stats.get('medium',0)} | Low: {stats.get('low',0)}")
        if self.firewall:
            try:
                blocked = self.firewall.get_blocked_ips()
                print(f"Blocked IPs: {len(blocked)} | {', '.join(blocked[:5]) if blocked else ''}")
            except: pass
        print("Logs saved to network_guard.log and forensics/")

# ============================
# Main Execution
# ============================
if __name__ == "__main__":
    print("\n" + "="*40)
    print("AI NETWORK SECURITY GUARD")
    print("REAL-TIME ATTACK DETECTION")
    print("="*40 + "\n")

    interface = NETWORK_CONFIG.get('default_interface', 'WiFi')
    detector = RealTimeAttackDetector(interface=interface)
    detector.start_monitoring()
