"""
Simple Dashboard for AI Network Security Guard
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import json
import os
from datetime import datetime

st.set_page_config(page_title="AI Security Guard", page_icon="🛡️", layout="wide")

# Title
st.title("🛡️ AI Network Security Guard")
st.markdown("Real-time Network Anomaly Detection Dashboard")

# Sidebar
with st.sidebar:
    st.header("⚙️ Settings")
    auto_refresh = st.checkbox("Auto-refresh", value=True)
    refresh_interval = st.slider("Refresh interval (sec)", 1, 10, 2)
    max_alerts = st.slider("Max alerts to show", 10, 100, 50)
    
    if st.button("🔄 Refresh Now"):
        st.rerun()

# Read alerts from log file
def read_alerts():
    log_file = 'logs/security_alerts.log'
    alerts = []
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-max_alerts:]:
                    try:
                        alert = json.loads(line.strip())
                        alerts.append(alert)
                    except:
                        pass
        except:
            pass
    
    return alerts

alerts = read_alerts()

# Display metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("📊 Total Alerts", len(alerts))

with col2:
    critical = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
    st.metric("🔴 Critical", critical)

with col3:
    high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
    st.metric("🟠 High", high)

with col4:
    medium = sum(1 for a in alerts if a.get('severity') == 'MEDIUM')
    st.metric("🟡 Medium", medium)

st.markdown("---")

# Alert table
st.subheader("🚨 Recent Alerts")

if alerts:
    data = []
    for alert in reversed(alerts):
        try:
            ts = alert.get('timestamp', '')
            if isinstance(ts, str) and 'T' in ts:
                time_str = ts.split('T')[1][:8]
            else:
                time_str = str(ts)[:8]
        except:
            time_str = 'N/A'
        
        data.append({
            'Time': time_str,
            'Severity': alert.get('severity', 'N/A'),
            'Protocol': alert.get('protocol', 'N/A'),
            'Source IP': alert.get('src_ip', 'Unknown'),
            'Dest IP': alert.get('dst_ip', 'Unknown'),
            'Score': f"{alert.get('anomaly_score', 0):.4f}",
            'Size': f"{alert.get('packet_size', 0)} B"
        })
    
    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True)
else:
    st.info("⏳ No alerts yet. System is monitoring...")
    st.code("""
Run in another terminal (as Administrator):
python real_time_monitor.py

Then generate traffic by browsing websites.
    """)

st.markdown("---")

# Charts
if alerts:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Severity Distribution")
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for alert in alerts:
            sev = alert.get('severity', 'LOW')
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(colors=['#FF0000', '#FF6600', '#FFAA00', '#00FF00']),
            hole=0.4
        )])
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("🌐 Protocol Distribution")
        protocol_counts = {}
        for alert in alerts:
            proto = alert.get('protocol', 'Unknown')
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        fig = go.Figure(data=[go.Bar(
            x=list(protocol_counts.keys()),
            y=list(protocol_counts.values()),
            marker_color='#3b82f6'
        )])
        fig.update_layout(height=300, xaxis_title='Protocol', yaxis_title='Count')
        st.plotly_chart(fig, use_container_width=True)

# Footer
st.markdown("---")
st.caption("🛡️ AI Network Security Guard | Real-time Threat Detection")

# Auto-refresh
if auto_refresh:
    import time
    time.sleep(refresh_interval)
    st.rerun()
