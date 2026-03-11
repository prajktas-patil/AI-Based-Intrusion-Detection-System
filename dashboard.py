"""
AI Network Security Guard - Real-Time Dashboard
Streamlit app for visualizing network anomalies in real-time
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import pyshark
import pickle
import numpy as np
import threading
import queue
import time

# Page configuration
st.set_page_config(
    page_title="AI Network Security Guard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

class DashboardMonitor:
    """Real-time network monitor for dashboard"""
    
    def __init__(self, interface='Wi-Fi'):
        self.interface = interface
        self.alerts = []
        self.running = False
        
        # Load model
        try:
            with open('anomaly_model.pkl', 'rb') as f:
                self.model = pickle.load(f)
            with open('scaler.pkl', 'rb') as f:
                self.scaler = pickle.load(f)
            with open('features.pkl', 'rb') as f:
                self.features = pickle.load(f)
            self.model_loaded = True
        except:
            self.model_loaded = False
        
        self.packets_analyzed = 0
        self.anomalies_detected = 0
    
    def extract_features(self, packet):
        """Extract features from packet"""
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
        
        try:
            if hasattr(packet, 'length'):
                features_dict['src_bytes'] = int(packet.length)
            
            if hasattr(packet, 'tcp'):
                features_dict['dst_bytes'] = int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
            elif hasattr(packet, 'udp'):
                features_dict['dst_bytes'] = int(packet.udp.length) if hasattr(packet.udp, 'length') else 0
        except:
            pass
        
        return features_dict
    
    def analyze_packet(self, packet):
        """Analyze packet and return alert if anomaly"""
        if not self.model_loaded:
            return None
        
        try:
            features_dict = self.extract_features(packet)
            X = np.array([[features_dict[f] for f in self.features]])
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            anomaly_score = self.model.score_samples(X_scaled)[0]
            
            self.packets_analyzed += 1
            
            if prediction == -1:
                self.anomalies_detected += 1
                
                protocol = 'TCP' if hasattr(packet, 'tcp') else 'UDP' if hasattr(packet, 'udp') else 'Other'
                src_ip = packet.ip.src if hasattr(packet, 'ip') else 'Unknown'
                dst_ip = packet.ip.dst if hasattr(packet, 'ip') else 'Unknown'
                
                severity = 'CRITICAL' if anomaly_score < -0.5 else 'HIGH' if anomaly_score < -0.3 else 'MEDIUM' if anomaly_score < -0.1 else 'LOW'
                
                alert = {
                    'timestamp': datetime.now(),
                    'protocol': protocol,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'severity': severity,
                    'score': anomaly_score,
                    'size': features_dict['src_bytes']
                }
                
                return alert
        except:
            pass
        
        return None

# Initialize session state
if 'monitor' not in st.session_state:
    st.session_state.monitor = DashboardMonitor()
if 'alerts_df' not in st.session_state:
    st.session_state.alerts_df = pd.DataFrame()
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False

# Dashboard Header
st.title("🛡️ AI Based Intrusion Detection System")
st.markdown("**Real-time Network Anomaly Detection Dashboard**")

# Sidebar
with st.sidebar:
    st.header("⚙️ Controls")
    
    interface = st.text_input("Network Interface", value="Wi-Fi", 
                              help="e.g., Wi-Fi, eth0, wlan0")
    
    if st.button("🔄 Update Interface"):
        st.session_state.monitor.interface = interface
        st.success(f"Interface updated to {interface}")
    
    st.markdown("---")
    
    st.header("📊 Statistics")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Packets", st.session_state.monitor.packets_analyzed)
    with col2:
        st.metric("Anomalies", st.session_state.monitor.anomalies_detected)
    
    if st.session_state.monitor.packets_analyzed > 0:
        anomaly_rate = (st.session_state.monitor.anomalies_detected / 
                       st.session_state.monitor.packets_analyzed) * 100
        st.metric("Anomaly Rate", f"{anomaly_rate:.2f}%")
    
    st.markdown("---")
    
    st.header("🎨 Severity Legend")
    st.markdown("🔴 **CRITICAL** - Immediate attention")
    st.markdown("🟠 **HIGH** - High priority")
    st.markdown("🟡 **MEDIUM** - Monitor closely")
    st.markdown("🟢 **LOW** - Low priority")

# Main content
if not st.session_state.monitor.model_loaded:
    st.error("⚠️ Model not found! Please run `train_model.py` first to train the AI.")
    st.stop()

# Status indicator
status_col1, status_col2, status_col3 = st.columns([1, 1, 2])
with status_col1:
    if st.session_state.monitoring:
        st.success("🟢 **MONITORING**")
    else:
        st.info("⚪ **STANDBY**")

with status_col2:
    st.info(f"**Interface:** {st.session_state.monitor.interface}")

with status_col3:
    st.info(f"**Last Update:** {datetime.now().strftime('%H:%M:%S')}")

st.markdown("---")

# Alert display area
st.header("🚨 Recent Anomalies")

# Create placeholder for live updates
alerts_placeholder = st.empty()

# Simulated demo mode (replace with actual packet capture in production)
demo_mode = st.checkbox("🎭 Demo Mode (Simulated Data)", value=False,
                       help="Enable to see simulated alerts without live capture")

if demo_mode:
    # Generate demo alerts
    if st.button("Generate Demo Alert"):
        demo_alert = {
            'timestamp': datetime.now(),
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
            'src_ip': f"192.168.1.{np.random.randint(1, 255)}",
            'dst_ip': f"203.0.113.{np.random.randint(1, 255)}",
            'severity': np.random.choice(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
            'score': np.random.uniform(-0.8, -0.05),
            'size': np.random.randint(64, 1500)
        }
        
        new_alert_df = pd.DataFrame([demo_alert])
        st.session_state.alerts_df = pd.concat([new_alert_df, st.session_state.alerts_df], 
                                               ignore_index=True)
        st.session_state.monitor.anomalies_detected += 1
        st.session_state.monitor.packets_analyzed += np.random.randint(5, 20)

# Display alerts table
if not st.session_state.alerts_df.empty:
    # Keep only last 50 alerts
    st.session_state.alerts_df = st.session_state.alerts_df.head(50)
    
    # Format display
    display_df = st.session_state.alerts_df.copy()
    display_df['timestamp'] = display_df['timestamp'].dt.strftime('%H:%M:%S')
    
    # Color code by severity
    def color_severity(val):
        colors = {
            'CRITICAL': 'background-color: #ff4444; color: white',
            'HIGH': 'background-color: #ff9933; color: white',
            'MEDIUM': 'background-color: #ffdd44; color: black',
            'LOW': 'background-color: #44ff44; color: black'
        }
        return colors.get(val, '')
    
    styled_df = display_df.style.applymap(color_severity, subset=['severity'])
    st.dataframe(styled_df, use_container_width=True, height=300)
    
    # Visualizations
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📈 Alerts by Severity")
        severity_counts = display_df['severity'].value_counts()
        fig_severity = px.pie(values=severity_counts.values, 
                             names=severity_counts.index,
                             color=severity_counts.index,
                             color_discrete_map={
                                 'CRITICAL': '#ff4444',
                                 'HIGH': '#ff9933',
                                 'MEDIUM': '#ffdd44',
                                 'LOW': '#44ff44'
                             })
        st.plotly_chart(fig_severity, use_container_width=True)
    
    with col2:
        st.subheader("🌐 Protocol Distribution")
        protocol_counts = display_df['protocol'].value_counts()
        fig_protocol = px.bar(x=protocol_counts.index, 
                             y=protocol_counts.values,
                             labels={'x': 'Protocol', 'y': 'Count'},
                             color=protocol_counts.values,
                             color_continuous_scale='Reds')
        st.plotly_chart(fig_protocol, use_container_width=True)
    
    # Timeline
    st.subheader("⏱️ Alert Timeline")
    timeline_df = st.session_state.alerts_df.copy()
    timeline_df['minute'] = timeline_df['timestamp'].dt.floor('1min')
    timeline_counts = timeline_df.groupby('minute').size().reset_index(name='count')
    
    fig_timeline = px.line(timeline_counts, x='minute', y='count',
                          labels={'minute': 'Time', 'count': 'Alerts'})
    fig_timeline.update_traces(line_color='#ff4444', line_width=2)
    st.plotly_chart(fig_timeline, use_container_width=True)

else:
    st.info("👁️ No anomalies detected yet. Your network looks clean!")

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: gray;'>
    <small>🛡️ AI Network Security Guard | Powered by Isolation Forest & Real-time Packet Analysis</small>
</div>
""", unsafe_allow_html=True)

# Auto-refresh
if demo_mode:
    time.sleep(2)
    st.rerun()
