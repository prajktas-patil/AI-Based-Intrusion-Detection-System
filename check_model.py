"""
Check if AI model is working correctly
"""

import pickle
import numpy as np

print("🔍 Checking AI Model Configuration")
print("=" * 50)

# Load model
try:
    with open('anomaly_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("✅ Model loaded successfully")
    
    with open('scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    print("✅ Scaler loaded successfully")
    
    with open('features.pkl', 'rb') as f:
        features = pickle.load(f)
    print(f"✅ Features loaded: {features}")
    
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit(1)

# Test with normal traffic pattern
print("\n📊 Testing with normal traffic pattern:")
normal_packet = np.array([[
    1.0,      # duration
    500,      # src_bytes
    250,      # dst_bytes  
    1,        # count
    1,        # srv_count
    0.0,      # serror_rate
    0.0,      # srv_serror_rate
    1.0,      # same_srv_rate
    0.0       # diff_srv_rate
]])

normal_scaled = scaler.transform(normal_packet)
normal_score = model.score_samples(normal_scaled)[0]
normal_pred = model.predict(normal_scaled)[0]

print(f"  Anomaly Score: {normal_score:.4f}")
print(f"  Prediction: {'ANOMALY' if normal_pred == -1 else 'NORMAL'}")
print(f"  Status: {'⚠️ ALERT' if normal_pred == -1 else '✅ OK'}")

# Test with suspicious pattern
print("\n🚨 Testing with suspicious traffic pattern:")
suspicious_packet = np.array([[
    0.1,      # very short duration
    60,       # very small bytes (port scan)
    0,        # no response
    50,       # many connections
    25,       # many different services
    0.8,      # high error rate
    0.9,      # high service error rate
    0.1,      # low same service rate
    0.9       # high different service rate
]])

suspicious_scaled = scaler.transform(suspicious_packet)
suspicious_score = model.score_samples(suspicious_scaled)[0]
suspicious_pred = model.predict(suspicious_scaled)[0]

print(f"  Anomaly Score: {suspicious_score:.4f}")
print(f"  Prediction: {'ANOMALY' if suspicious_pred == -1 else 'NORMAL'}")
print(f"  Status: {'⚠️ ALERT' if suspicious_pred == -1 else '✅ OK'}")

# Show threshold
print(f"\n📏 Current Detection Threshold:")
print(f"  Scores below -0.1 trigger alerts")
print(f"  Normal traffic score: {normal_score:.4f}")
print(f"  Suspicious traffic score: {suspicious_score:.4f}")

if suspicious_pred != -1:
    print("\n⚠️ WARNING: Suspicious pattern not detected!")
    print("   Model may need retraining or threshold adjustment")
else:
    print("\n✅ Model is correctly identifying anomalies")
