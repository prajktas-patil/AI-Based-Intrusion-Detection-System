"""
AI Network Security Guard - Model Training
Trains an Isolation Forest model on NSL-KDD dataset to learn normal network behavior
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle
import urllib.request
import os

def download_nsl_kdd():
    """Download NSL-KDD dataset if not present"""
    print("📥 Downloading NSL-KDD dataset...")
    
    train_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    
    if not os.path.exists('KDDTrain.txt'):
        urllib.request.urlretrieve(train_url, 'KDDTrain.txt')
        print("✅ Dataset downloaded!")
    else:
        print("✅ Dataset already exists!")

def load_and_preprocess_data():
    """Load NSL-KDD data and prepare it for training"""
    print("🔄 Loading and preprocessing data...")
    
    # Column names for NSL-KDD dataset
    columns = [
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
    ]
    
    # Load data
    df = pd.read_csv('KDDTrain.txt', names=columns, header=None)
    
    # Filter only NORMAL traffic for training (learning what's normal)
    normal_data = df[df['label'] == 'normal'].copy()
    print(f"📊 Found {len(normal_data)} normal connections to learn from")
    
    # Select important features for network analysis
    features = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count',
                'serror_rate', 'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate']
    
    X_normal = normal_data[features].copy()
    
    # Handle any missing values
    X_normal = X_normal.fillna(0)
    
    return X_normal, features

def train_anomaly_detector(X_normal):
    """Train Isolation Forest model on normal traffic"""
    print("🧠 Training AI to learn normal behavior...")
    
    # Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    
    # Train Isolation Forest
    # contamination=0.01 means we expect ~1% anomalies
    model = IsolationForest(
        contamination=0.01,
        random_state=42,
        n_estimators=100,
        max_samples='auto',
        verbose=1
    )
    
    model.fit(X_scaled)
    print("✅ Model trained successfully!")
    
    return model, scaler

def save_model(model, scaler, features):
    """Save trained model and preprocessing objects"""
    print("💾 Saving model...")
    
    with open('anomaly_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    with open('features.pkl', 'wb') as f:
        pickle.dump(features, f)
    
    print("✅ Model saved! Ready for real-time detection.")

def main():
    """Main training pipeline"""
    print("=" * 60)
    print("🛡️  AI Network Security Guard - Training Phase")
    print("=" * 60)
    
    # Download dataset
    download_nsl_kdd()
    
    # Load and preprocess
    X_normal, features = load_and_preprocess_data()
    
    # Train model
    model, scaler = train_anomaly_detector(X_normal)
    
    # Save everything
    save_model(model, scaler, features)
    
    print("\n" + "=" * 60)
    print("🎉 Training complete! You can now run the live detector.")
    print("=" * 60)

if __name__ == "__main__":
    main()
