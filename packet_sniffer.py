"""
AI Network Security Guard - Live Packet Sniffer
Captures real-time network traffic and analyzes it for anomalies
"""

import pyshark
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
import queue
import threading

class NetworkSniffer:
    """Real-time network packet sniffer and analyzer"""
    
    def __init__(self, interface='Wi-Fi'):
        """Initialize sniffer with network interface"""
        self.interface = interface
        self.alert_queue = queue.Queue()
        
        # Load trained model
        print("📦 Loading AI model...")
        with open('anomaly_model.pkl', 'rb') as f:
            self.model = pickle.load(f)
        
        with open('scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        with open('features.pkl', 'rb') as f:
            self.features = pickle.load(f)
        
        print("✅ Model loaded successfully!")
        
        # Statistics
        self.packets_analyzed = 0
        self.anomalies_detected = 0
    
    def extract_features(self, packet):
        """Extract relevant features from a network packet"""
        try:
            features_dict = {
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
            
            # Extract packet length
            if hasattr(packet, 'length'):
                features_dict['src_bytes'] = int(packet.length)
            
            # Extract TCP/UDP specific info
            if hasattr(packet, 'tcp'):
                features_dict['dst_bytes'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
            elif hasattr(packet, 'udp'):
                features_dict['dst_bytes'] = int(packet.udp.length) if hasattr(packet.udp, 'length') else 0
            
            return features_dict
            
        except Exception as e:
            # Return default features if extraction fails
            return {feature: 0 for feature in self.features}
    
    def analyze_packet(self, packet):
        """Analyze a single packet for anomalies"""
        try:
            # Extract features
            features_dict = self.extract_features(packet)
            
            # Create feature vector in correct order
            X = np.array([[features_dict[f] for f in self.features]])
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Predict (-1 = anomaly, 1 = normal)
            prediction = self.model.predict(X_scaled)[0]
            anomaly_score = self.model.score_samples(X_scaled)[0]
            
            self.packets_analyzed += 1
            
            if prediction == -1:
                # ANOMALY DETECTED!
                self.anomalies_detected += 1
                
                alert = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'protocol': self._get_protocol(packet),
                    'src_ip': self._get_src_ip(packet),
                    'dst_ip': self._get_dst_ip(packet),
                    'severity': self._calculate_severity(anomaly_score),
                    'anomaly_score': anomaly_score,
                    'packet_size': features_dict['src_bytes']
                }
                
                self.alert_queue.put(alert)
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error analyzing packet: {e}")
            return False
    
    def _get_protocol(self, packet):
        """Extract protocol from packet"""
        if hasattr(packet, 'tcp'):
            return 'TCP'
        elif hasattr(packet, 'udp'):
            return 'UDP'
        elif hasattr(packet, 'icmp'):
            return 'ICMP'
        else:
            return 'Other'
    
    def _get_src_ip(self, packet):
        """Extract source IP"""
        if hasattr(packet, 'ip'):
            return packet.ip.src
        return 'Unknown'
    
    def _get_dst_ip(self, packet):
        """Extract destination IP"""
        if hasattr(packet, 'ip'):
            return packet.ip.dst
        return 'Unknown'
    
    def _calculate_severity(self, score):
        """Calculate severity based on anomaly score"""
        if score < -0.5:
            return 'CRITICAL'
        elif score < -0.3:
            return 'HIGH'
        elif score < -0.1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def start_sniffing(self, packet_count=100):
        """Start capturing and analyzing packets"""
        print(f"👁️  Starting network monitoring on {self.interface}...")
        print("🔍 Press Ctrl+C to stop\n")
        
        try:
            # Create packet capture
            capture = pyshark.LiveCapture(interface=self.interface)
            
            # Process packets
            for packet in capture.sniff_continuously(packet_count=packet_count):
                self.analyze_packet(packet)
                
                # Print progress every 10 packets
                if self.packets_analyzed % 10 == 0:
                    print(f"📊 Analyzed: {self.packets_analyzed} packets | "
                          f"🚨 Anomalies: {self.anomalies_detected}")
            
        except KeyboardInterrupt:
            print("\n⏹️  Stopping network monitor...")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.print_summary()
    
    def print_summary(self):
        """Print analysis summary"""
        print("\n" + "=" * 60)
        print("📈 MONITORING SUMMARY")
        print("=" * 60)
        print(f"Total Packets Analyzed: {self.packets_analyzed}")
        print(f"Anomalies Detected: {self.anomalies_detected}")
        if self.packets_analyzed > 0:
            anomaly_rate = (self.anomalies_detected / self.packets_analyzed) * 100
            print(f"Anomaly Rate: {anomaly_rate:.2f}%")
        print("=" * 60)

def main():
    """Main function to run the sniffer"""
    print("=" * 60)
    print("🛡️  AI Network Security Guard - Live Monitor")
    print("=" * 60)
    
    # Note: You may need to change 'Wi-Fi' to your actual interface name
    # On Linux: usually 'eth0', 'wlan0', etc.
    # On Windows: 'Wi-Fi', 'Ethernet', etc.
    # On Mac: 'en0', 'en1', etc.
    
    interface = 'Wi-Fi'  # Change this to your network interface
    
    sniffer = NetworkSniffer(interface=interface)
    sniffer.start_sniffing(packet_count=100)

if __name__ == "__main__":
    main()
