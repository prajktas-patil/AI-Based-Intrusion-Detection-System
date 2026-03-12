"""
Real-Time Dashboard - Reads actual data from monitoring system
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import json
import os
import time

st.set_page_config(
    page_title="AI Security Guard - Live",
    page_icon="🛡️",
    layout="wide"
)

# Professional Dark Theme
PROFESSIONAL_THEME = """
<style>

.stApp {
    background-color: #ffffff;
    color: #000000;
    font-family: Arial, sans-serif;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #f5f5f5;
    border-right: 1px solid #dddddd;
}

/* Metrics */
[data-testid="stMetricValue"] {
    color: #000000;
    font-size: 20px;
    font-weight: 600;
}

[data-testid="stMetricLabel"] {
    color: #555555;
    font-size: 13px;
}

/* Titles */
h1 {
    color: #000000 !important;
    text-align: center;
    font-weight: 600;
    border-bottom: 1px solid #dddddd;
    padding-bottom: 10px;
}

h2 {
    color: #333333 !important;
    font-weight: 500;
}

/* Tables */
.dataframe {
    background-color: #ffffff !important;
    color: #000000 !important;
}

.dataframe th {
    background-color: #eeeeee !important;
    color: #000000 !important;
    border-bottom: 1px solid #dddddd !important;
}

.dataframe td {
    background-color: #ffffff !important;
    border-bottom: 1px solid #eeeeee !important;
}

/* Severity badges */
.critical-badge {
    background-color: #ff4d4d;
    color: white;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 12px;
}

.high-badge {
    background-color: #ff944d;
    color: white;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 12px;
}

.medium-badge {
    background-color: #ffd24d;
    color: black;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 12px;
}

.low-badge {
    background-color: #66cc66;
    color: white;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 12px;
}

/* Status */
.status-online {
    color: green;
    font-weight: 600;
}

.status-blocked {
    color: red;
    font-weight: 600;
}

</style>
"""

st.markdown(PROFESSIONAL_THEME, unsafe_allow_html=True)

# Header
st.markdown("""
<h1 class="glow-text">
🛡️ AI NETWORK SECURITY GUARD - LIVE MONITORING 🛡️
</h1>
<p style="text-align: center; color: #00BFFF; font-family: 'Courier New'; font-size: 16px;">
REAL-TIME THREAT DETECTION & AUTOMATIC DEFENSE SYSTEM
</p>
""", unsafe_allow_html=True)

# Function to read alerts from log file
def read_alerts_from_log(max_alerts=100):
    alerts = []
    log_file = 'logs/security_alerts.log'
    
    if not os.path.exists(log_file):
        return []
    
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
            for line in lines[-max_alerts:]:
                try:
                    alert = json.loads(line.strip())
                    alerts.append(alert)
                except:
                    pass
    except Exception as e:
        st.error(f"Error reading logs: {e}")
    
    return alerts

# Function to read blocked IPs
def read_blocked_ips():
    blocked_file = 'data/blocked_ips.json'
    
    if not os.path.exists(blocked_file):
        return {}
    
    try:
        with open(blocked_file, 'r') as f:
            return json.load(f)
    except:
        return {}

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ CONTROL PANEL")
    
    st.markdown("### 📊 SYSTEM STATUS")
    
    # Check if monitoring is running
    log_file = 'logs/security_alerts.log'
    if os.path.exists(log_file):
        # Check if file was modified recently (last 30 seconds)
        mod_time = os.path.getmtime(log_file)
        time_diff = time.time() - mod_time
        
        if time_diff < 30:
            st.markdown(f"<p class='status-online'>🟢 MONITORING ACTIVE</p>", unsafe_allow_html=True)
        else:
            st.markdown(f"<p style='color: #FF6600;'>🟡 MONITORING IDLE ({int(time_diff)}s ago)</p>", unsafe_allow_html=True)
    else:
        st.markdown(f"<p style='color: #FF0000;'>🔴 NO DATA - START MONITOR</p>", unsafe_allow_html=True)
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(f"**Time:** {current_time}")
    
    st.markdown("---")
    
    st.markdown("### 🔄 REFRESH")
    auto_refresh = st.checkbox("Auto-refresh", value=True)
    refresh_interval = st.slider("Interval (sec)", 1, 10, 2)
    
    if st.button("🔄 Manual Refresh"):
        st.rerun()
    
    st.markdown("---")
    
    st.markdown("### 🔍 FILTERS")
    max_alerts_display = st.slider("Max Alerts", 10, 100, 50)

# Read data
alerts = read_alerts_from_log(max_alerts_display)
blocked_ips = read_blocked_ips()

# Calculate statistics
total_alerts = len(alerts)
severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

for alert in alerts:
    severity = alert.get('severity', 'UNKNOWN')
    if severity in severity_counts:
        severity_counts[severity] += 1

# Top metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🚨 TOTAL ALERTS",
        value=total_alerts,
        delta=f"+{total_alerts % 100}"
    )

with col2:
    st.metric(
        label="🔴 CRITICAL",
        value=severity_counts['CRITICAL'],
        delta=f"+{severity_counts['CRITICAL']}" if severity_counts['CRITICAL'] > 0 else "0"
    )

with col3:
    st.metric(
        label="🚫 BLOCKED IPs",
        value=len(blocked_ips),
        delta=f"+{len(blocked_ips)}" if len(blocked_ips) > 0 else "0"
    )

with col4:
    high_medium = severity_counts['HIGH'] + severity_counts['MEDIUM']
    st.metric(
        label="⚠️ HIGH + MEDIUM",
        value=high_medium,
        delta=f"+{high_medium}" if high_medium > 0 else "0"
    )

st.markdown("---")

# Recent alerts table
st.markdown("## 🚨 RECENT SECURITY ALERTS (LIVE)")

if alerts:
    alert_data = []
    for alert in reversed(alerts[-max_alerts_display:]):
        severity_map = {
            'CRITICAL': 'critical-badge',
            'HIGH': 'high-badge',
            'MEDIUM': 'medium-badge',
            'LOW': 'low-badge'
        }
        badge_class = severity_map.get(alert['severity'], 'low-badge')
        severity_badge = f"<span class='{badge_class}'>{alert['severity']}</span>"
        
        # Parse timestamp
        try:
            if isinstance(alert.get('timestamp'), str):
                ts = datetime.fromisoformat(alert['timestamp'])
                time_str = ts.strftime("%H:%M:%S")
            else:
                time_str = str(alert.get('timestamp', 'N/A'))
        except:
            time_str = str(alert.get('timestamp', 'N/A'))
        
        alert_data.append({
            "⏰ Time": time_str,
            "🎯 Severity": severity_badge,
            "🌐 Protocol": alert.get('protocol', 'N/A'),
            "📍 Source": alert.get('src_ip', 'Unknown'),
            "📍 Destination": alert.get('dst_ip', 'Unknown'),
            "📊 Score": f"{alert.get('anomaly_score', 0):.4f}",
            "📦 Size": f"{alert.get('packet_size', 0)} B"
        })
    
    df = pd.DataFrame(alert_data)
    st.markdown(df.to_html(escape=False, index=False), unsafe_allow_html=True)
else:
    st.info("⏳ Waiting for alerts... Make sure realtime_monitor.py is running!")
    st.code("""
    To start monitoring:
    
    # Terminal 1 (as Admin):
    python real_time_monitor.py
    
    # Then refresh this dashboard
    """)

st.markdown("---")

# Charts
if alerts:
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("## 📊 SEVERITY DISTRIBUTION")
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(
                colors=['#FF0000', '#FF6600', '#FFAA00', '#00FF00'],
                line=dict(color='#000000', width=2)
            ),
            textfont=dict(size=14, color='#FFFFFF', family='Courier New'),
            hole=0.4
        )])
        
        fig.update_layout(
            plot_bgcolor='#000000',
            paper_bgcolor='#0a0a0a',
            font=dict(color='#FFFFFF', family='Courier New'),
            showlegend=True,
            legend=dict(
                bgcolor='#1a1a1a',
                bordercolor='#00FF41',
                borderwidth=1
            ),
            height=350
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("## 🌐 PROTOCOL ANALYSIS")
        
        protocol_counts = {}
        for alert in alerts:
            proto = alert.get('protocol', 'Unknown')
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        if protocol_counts:
            fig = go.Figure(data=[go.Bar(
                x=list(protocol_counts.keys()),
                y=list(protocol_counts.values()),
                marker=dict(
                    color='#00FF41',
                    line=dict(color='#00BFFF', width=2)
                ),
                text=list(protocol_counts.values()),
                textposition='outside',
                textfont=dict(color='#FFFFFF', family='Courier New')
            )])
            
            fig.update_layout(
                plot_bgcolor='#000000',
                paper_bgcolor='#0a0a0a',
                font=dict(color='#FFFFFF', family='Courier New'),
                xaxis=dict(gridcolor='#333333', showgrid=True),
                yaxis=dict(gridcolor='#333333', showgrid=True),
                height=350
            )
            
            st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# Firewall status
if blocked_ips:
    st.markdown("## 🔥 FIREWALL STATUS")
    
    st.markdown(f"<p class='status-blocked'>🚫 {len(blocked_ips)} IP(S) CURRENTLY BLOCKED</p>", unsafe_allow_html=True)
    
    for ip, data in list(blocked_ips.items())[:10]:
        st.text(f"🔴 {ip} - {data.get('severity', 'N/A')} - {data.get('reason', 'N/A')}")
else:
    st.markdown("## 🔥 FIREWALL STATUS")
    st.markdown("<p class='status-online'>✅ NO THREATS BLOCKED - SYSTEM SECURE</p>", unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<p style="text-align: center; color: #666666; font-family: 'Courier New'; font-size: 12px;">
🛡️ AI Network Security Guard | Real-time Threat Detection System | Protected by Advanced AI
</p>
""", unsafe_allow_html=True)

# Auto-refresh
if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()
