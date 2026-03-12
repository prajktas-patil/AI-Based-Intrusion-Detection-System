"""
Test monitor with lower detection threshold
"""

# Temporarily modify the detection threshold
import real_time_monitor
import numpy as np

# Monkey-patch the detect_attack method to be more sensitive
original_detect = real_time_monitor.RealTimeAttackDetector.detect_attack

def sensitive_detect(self, features):
    """More sensitive detection for testing"""
    try:
        feature_array = np.array([[
            features['duration'],
            features['src_bytes'],
            features['dst_bytes'],
            features['count'],
            features['srv_count'],
            features['serror_rate'],
            features['srv_serror_rate'],
            features['same_srv_rate'],
            features['diff_srv_rate']
        ]])
        
        feature_array_scaled = self.scaler.transform(feature_array)
        anomaly_score = self.model.score_samples(feature_array_scaled)[0]
        
        # LOWER THRESHOLD - More sensitive!
        # Original: -0.1, New: -0.05
        is_anomaly = anomaly_score < -0.05
        
        return is_anomaly, anomaly_score
        
    except Exception as e:
        return False, 0.0

# Replace the method
real_time_monitor.RealTimeAttackDetector.detect_attack = sensitive_detect

# Now run the monitor
if __name__ == "__main__":
    from config_enhanced import NETWORK_CONFIG
    
    interface = NETWORK_CONFIG.get('default_interface', 'WiFi')
    detector = real_time_monitor.RealTimeAttackDetector(interface=interface)
    detector.start_monitoring()
