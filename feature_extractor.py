"""
AI Network Security Guard - Feature Extractor
Advanced feature extraction from network packets
"""

import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, deque
from utils import logger

class PacketFeatureExtractor:
    """
    Advanced feature extraction from network packets
    Maintains state to calculate time-based and connection-based features
    """
    
    def __init__(self, window_size=100):
        """
        Initialize feature extractor
        
        Args:
            window_size: Number of recent packets to maintain for windowed features
        """
        self.window_size = window_size
        
        # Connection tracking
        self.connections = defaultdict(lambda: {
            'start_time': None,
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocol': None,
            'flags': [],
            'last_seen': None,
        })
        
        # Recent packets window (for time-based features)
        self.recent_packets = deque(maxlen=window_size)
        
        # Service tracking
        self.services = defaultdict(int)
        self.service_errors = defaultdict(int)
        
        # Host tracking
        self.src_hosts = defaultdict(int)
        self.dst_hosts = defaultdict(int)
        
        # Statistics
        self.total_packets = 0
        self.total_bytes = 0
        
        logger.info(f"🔧 Feature extractor initialized with window size: {window_size}")
    
    def extract_basic_features(self, packet):
        """Extract basic features from a single packet"""
        features = {
            'duration': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
        }
        
        try:
            # Packet size
            if hasattr(packet, 'length'):
                features['src_bytes'] = int(packet.length)
            
            # Protocol-specific bytes
            if hasattr(packet, 'tcp'):
                features['dst_bytes'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
                features['protocol'] = 'TCP'
            elif hasattr(packet, 'udp'):
                features['dst_bytes'] = int(packet.udp.length) if hasattr(packet.udp, 'length') else 0
                features['protocol'] = 'UDP'
            elif hasattr(packet, 'icmp'):
                features['protocol'] = 'ICMP'
            else:
                features['protocol'] = 'Other'
            
            # Extract IPs
            if hasattr(packet, 'ip'):
                features['src_ip'] = packet.ip.src
                features['dst_ip'] = packet.ip.dst
            
            # Extract ports
            if hasattr(packet, 'tcp'):
                features['src_port'] = int(packet.tcp.srcport) if hasattr(packet.tcp, 'srcport') else 0
                features['dst_port'] = int(packet.tcp.dstport) if hasattr(packet.tcp, 'dstport') else 0
            elif hasattr(packet, 'udp'):
                features['src_port'] = int(packet.udp.srcport) if hasattr(packet.udp, 'srcport') else 0
                features['dst_port'] = int(packet.udp.dstport) if hasattr(packet.udp, 'dstport') else 0
            
        except Exception as e:
            logger.debug(f"Error extracting basic features: {e}")
        
        return features
    
    def extract_connection_features(self, packet):
        """Extract connection-based features"""
        basic = self.extract_basic_features(packet)
        
        # Create connection key
        conn_key = f"{basic.get('src_ip', 'unknown')}:{basic.get('src_port', 0)}-" \
                   f"{basic.get('dst_ip', 'unknown')}:{basic.get('dst_port', 0)}"
        
        # Update connection state
        conn = self.connections[conn_key]
        current_time = datetime.now()
        
        if conn['start_time'] is None:
            conn['start_time'] = current_time
        
        conn['packet_count'] += 1
        conn['bytes_sent'] += basic.get('src_bytes', 0)
        conn['bytes_received'] += basic.get('dst_bytes', 0)
        conn['protocol'] = basic.get('protocol', 'Unknown')
        conn['last_seen'] = current_time
        
        # Calculate duration
        duration = (current_time - conn['start_time']).total_seconds()
        
        # Enhanced features
        features = {
            'duration': duration,
            'src_bytes': basic.get('src_bytes', 0),
            'dst_bytes': basic.get('dst_bytes', 0),
            'count': conn['packet_count'],
            'total_bytes': conn['bytes_sent'] + conn['bytes_received'],
            'bytes_ratio': (conn['bytes_sent'] / (conn['bytes_received'] + 1)),
        }
        
        return features
    
    def extract_time_based_features(self, packet):
        """Extract time-based windowed features"""
        current_time = datetime.now()
        
        # Add packet to window
        packet_info = {
            'time': current_time,
            'protocol': self.extract_basic_features(packet).get('protocol', 'Unknown'),
            'src_ip': self.extract_basic_features(packet).get('src_ip', 'unknown'),
            'dst_ip': self.extract_basic_features(packet).get('dst_ip', 'unknown'),
            'bytes': self.extract_basic_features(packet).get('src_bytes', 0),
        }
        self.recent_packets.append(packet_info)
        
        # Calculate windowed features
        if len(self.recent_packets) < 2:
            return {
                'srv_count': 1,
                'same_srv_rate': 1.0,
                'diff_srv_rate': 0.0,
                'serror_rate': 0.0,
                'srv_serror_rate': 0.0,
            }
        
        # Count same service connections
        current_dst = packet_info['dst_ip']
        same_srv = sum(1 for p in self.recent_packets if p['dst_ip'] == current_dst)
        diff_srv = len(self.recent_packets) - same_srv
        
        features = {
            'srv_count': same_srv,
            'same_srv_rate': same_srv / len(self.recent_packets),
            'diff_srv_rate': diff_srv / len(self.recent_packets),
            'serror_rate': 0.0,  # Placeholder
            'srv_serror_rate': 0.0,  # Placeholder
        }
        
        return features
    
    def extract_host_based_features(self, packet):
        """Extract host-based features"""
        basic = self.extract_basic_features(packet)
        
        src_ip = basic.get('src_ip', 'unknown')
        dst_ip = basic.get('dst_ip', 'unknown')
        
        # Update host counters
        self.src_hosts[src_ip] += 1
        self.dst_hosts[dst_ip] += 1
        
        # Calculate host-based features
        features = {
            'dst_host_count': self.dst_hosts[dst_ip],
            'src_host_count': self.src_hosts[src_ip],
            'dst_host_same_src_port_rate': 1.0,  # Simplified
            'dst_host_srv_count': self.dst_hosts[dst_ip],
        }
        
        return features
    
    def extract_all_features(self, packet):
        """
        Extract all features from a packet
        Combines basic, connection, time-based, and host-based features
        """
        try:
            basic = self.extract_basic_features(packet)
            connection = self.extract_connection_features(packet)
            time_based = self.extract_time_based_features(packet)
            host_based = self.extract_host_based_features(packet)
            
            # Combine all features
            all_features = {**basic, **connection, **time_based, **host_based}
            
            # Update global statistics
            self.total_packets += 1
            self.total_bytes += all_features.get('src_bytes', 0)
            
            return all_features
            
        except Exception as e:
            logger.error(f"Error extracting all features: {e}")
            return self._get_default_features()
    
    def _get_default_features(self):
        """Return default features if extraction fails"""
        return {
            'duration': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'same_srv_rate': 1.0,
            'diff_srv_rate': 0,
        }
    
    def get_feature_vector(self, features, feature_names):
        """
        Convert feature dictionary to ordered vector for model input
        
        Args:
            features: Dictionary of features
            feature_names: List of feature names in correct order
            
        Returns:
            NumPy array of feature values
        """
        return np.array([features.get(name, 0) for name in feature_names])
    
    def reset_state(self):
        """Reset all tracking state"""
        self.connections.clear()
        self.recent_packets.clear()
        self.services.clear()
        self.service_errors.clear()
        self.src_hosts.clear()
        self.dst_hosts.clear()
        self.total_packets = 0
        self.total_bytes = 0
        logger.info("🔄 Feature extractor state reset")
    
    def get_statistics(self):
        """Get current statistics"""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'active_connections': len(self.connections),
            'unique_src_hosts': len(self.src_hosts),
            'unique_dst_hosts': len(self.dst_hosts),
            'window_size': len(self.recent_packets),
        }
    
    def cleanup_old_connections(self, timeout_seconds=300):
        """Remove old inactive connections"""
        current_time = datetime.now()
        timeout = timedelta(seconds=timeout_seconds)
        
        old_connections = [
            key for key, conn in self.connections.items()
            if conn['last_seen'] and (current_time - conn['last_seen']) > timeout
        ]
        
        for key in old_connections:
            del self.connections[key]
        
        if old_connections:
            logger.debug(f"🧹 Cleaned up {len(old_connections)} old connections")


class AdvancedFeatureAnalyzer:
    """
    Advanced analysis of extracted features
    Provides insights and pattern detection
    """
    
    def __init__(self):
        self.protocol_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packet_size_distribution = []
        
    def analyze_packet_pattern(self, features):
        """Analyze packet for suspicious patterns"""
        alerts = []
        
        # Check for unusually large packets
        if features.get('src_bytes', 0) > 1500:
            alerts.append({
                'type': 'LARGE_PACKET',
                'message': f"Unusually large packet: {features['src_bytes']} bytes"
            })
        
        # Check for rapid connections
        if features.get('count', 0) > 100:
            alerts.append({
                'type': 'RAPID_CONNECTIONS',
                'message': f"High connection count: {features['count']}"
            })
        
        # Check for port scanning behavior
        if features.get('diff_srv_rate', 0) > 0.8:
            alerts.append({
                'type': 'POSSIBLE_SCAN',
                'message': "High different service rate (possible port scan)"
            })
        
        return alerts
    
    def get_protocol_distribution(self):
        """Get distribution of protocols"""
        return dict(self.protocol_stats)
    
    def get_top_ports(self, n=10):
        """Get top N most accessed ports"""
        return sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:n]


# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    'PacketFeatureExtractor',
    'AdvancedFeatureAnalyzer',
]
