# 🛡️ AI Network Security Guard - Enhanced Edition

An AI-powered network security system with **Auto-Blocking Firewall**, **Multi-Channel Instant Alerts** (Telegram/Email/SMS), and **Advanced Forensic Logging** to catch Zero-Day attacks in real-time.

## 🌟 What's New in Enhanced Edition

### 🔥 **Auto-Block Firewall**
- **Automatic IP blocking** when threats are detected
- Cross-platform support (Windows, Linux, macOS)
- Configurable blocking thresholds and duration
- Whitelist support for trusted IPs
- Automatic unblocking after timeout

### 📱 **Instant Multi-Channel Alerts**
- **Telegram Bot Integration** - Get instant push notifications on your phone
- **Email Alerts** with detailed threat information
- **SMS Alerts** via Twilio for critical threats
- **Slack Integration** for team notifications
- Sound alerts for immediate attention

### 📊 **Forensic Logging & Reports**
- Comprehensive packet capture and analysis
- Automatic daily/weekly security reports
- PCAP file storage for deep investigation
- Attack pattern recognition and classification
- GeoIP lookup for attacker location
- Detailed connection metadata logging

---

## 🎯 Key Features

### Traditional Features
- ✅ **Learns** normal network behavior automatically
- ✅ **Monitors** live network traffic in real-time
- ✅ **Detects** suspicious activity using AI (Isolation Forest)
- ✅ **Alerts** instantly through beautiful dashboard

### 🆕 Enhanced Features
- 🔥 **Auto-blocks** malicious IPs at the firewall level
- 📱 **Instant notifications** to your phone via Telegram
- 📧 **Email & SMS** alerts for critical threats
- 📊 **Forensic reports** with detailed attack analysis
- 🗺️ **GeoIP tracking** to see where attacks come from
- 💾 **PCAP capture** for security investigations
- 📈 **Attack pattern** recognition (DDoS, Port Scan, etc.)

---

## 🏗️ Enhanced System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                  ENHANCED AI SECURITY GUARD                     │
└────────────────────────────────────────────────────────────────┘

1. CONFIGURATION (config_enhanced.py)
   ├── Firewall settings & whitelists
   ├── Telegram/SMS/Email configuration
   ├── Forensic logging parameters
   └── Auto-block thresholds

2. TRAINING PHASE (train_model.py)
   ├── Download NSL-KDD dataset
   ├── Train Isolation Forest AI
   └── Save trained model

3. MONITORING (packet_sniffer.py)
   ├── Capture live packets with PyShark
   ├── Extract network features
   ├── AI anomaly detection
   └── Flag suspicious activity

4. 🆕 FIREWALL MANAGER (firewall_manager.py)
   ├── Cross-platform IP blocking
   ├── Automatic threat mitigation
   ├── Whitelist management
   └── Block expiration handling

5. 🆕 ENHANCED ALERTS (alert_manager_enhanced.py)
   ├── Multi-channel notifications
   ├── Alert correlation & deduplication
   ├── Auto-block trigger logic
   └── Attack pattern analysis

6. 🆕 ENHANCED UTILITIES (utils_enhanced.py)
   ├── Telegram Bot integration
   ├── SMS alerts via Twilio
   ├── Forensic data logging
   ├── PCAP packet capture
   └── Comprehensive report generation

7. VISUALIZATION (dashboard.py)
   ├── Real-time dashboard
   ├── Blocked IPs display
   ├── Forensic data viewer
   └── Attack pattern visualization
```

---

## 📋 Prerequisites

### Required Software
- **Python 3.8+**
- **Wireshark/TShark** (for PyShark to work)
  - Windows: Download from https://www.wireshark.org/
  - Mac: `brew install wireshark`
  - Linux: `sudo apt-get install tshark`

### System Permissions
- **Administrator/Root access** for:
  - Packet capture
  - Firewall rule management
  - System-level blocking

### Optional Services
- **Telegram Bot Token** (from @BotFather) - for instant mobile alerts
- **Twilio Account** - for SMS notifications
- **Slack Webhook** - for team notifications

---

## 🚀 Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements_enhanced.txt
```

### Step 2: Configure Telegram Bot (Recommended)

1. **Create a Telegram Bot:**
   - Open Telegram and search for `@BotFather`
   - Send `/newbot` and follow instructions
   - Copy the bot token (looks like: `123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`)

2. **Get Your Chat ID:**
   - Search for `@userinfobot` on Telegram
   - Send `/start` to get your chat ID

3. **Update Configuration:**
   ```python
   # In config_enhanced.py
   'telegram_enabled': True,
   'telegram_bot_token': 'YOUR_BOT_TOKEN',
   'telegram_chat_ids': ['YOUR_CHAT_ID'],
   ```

### Step 3: Configure Email Alerts (Optional)

```python
# In config_enhanced.py
'email_enabled': True,
'email_smtp_server': 'smtp.gmail.com',
'email_smtp_port': 587,
'email_sender': 'your_email@gmail.com',
'email_password': 'your_app_password',  # Use App Password for Gmail
'email_recipients': ['admin@company.com'],
```

**Gmail App Password Setup:**
1. Go to Google Account settings
2. Security → 2-Step Verification
3. App passwords → Generate new password
4. Use this password in config

### Step 4: Configure Firewall Settings

```python
# In config_enhanced.py
FIREWALL_CONFIG = {
    'auto_block_enabled': True,
    'block_on_severity': ['CRITICAL', 'HIGH'],
    'block_threshold_count': 3,  # Block after 3 alerts
    'block_duration_minutes': 60,  # Block for 1 hour
    'whitelist_ips': [
        '127.0.0.1',
        '192.168.1.1',  # Add your trusted IPs
    ],
}
```

---

## 💻 Usage

### Phase 1: Train the AI Brain 🧠

```bash
python train_model.py
```

**Output files:**
- `anomaly_model.pkl` - Trained AI model
- `scaler.pkl` - Feature normalization
- `features.pkl` - Feature list

---

### Phase 2: Start Monitoring with Auto-Protection 🛡️

#### Option A: Command Line Mode

```bash
# Windows (Run as Administrator)
python packet_sniffer.py

# Linux/Mac (Run with sudo)
sudo python packet_sniffer.py
```

**What happens:**
- 📊 Monitors network traffic in real-time
- 🤖 AI detects anomalies instantly
- 🚨 Alerts sent to Telegram/Email/SMS
- 🔥 Malicious IPs auto-blocked at firewall level
- 📝 All activity logged for forensics

#### Option B: Dashboard Mode (Recommended)

```bash
# Windows (Run as Administrator)
streamlit run dashboard.py

# Linux/Mac (Run with sudo)
sudo streamlit run dashboard.py
```

**Dashboard Features:**
- 🚨 Real-time anomaly alerts
- 🔥 Live blocked IPs display
- 📈 Attack pattern visualization
- 📊 Severity breakdown charts
- 🌐 Protocol distribution
- ⏱️ Alert timeline
- 📱 Notification status

**Access:** Opens at `http://localhost:8501`

---

## 🔥 Firewall Auto-Block Features

### How Auto-Blocking Works

1. **Threat Detection** - AI detects anomalous behavior
2. **Threshold Check** - Compares against configured thresholds
3. **Whitelist Check** - Ensures IP is not trusted
4. **Automatic Block** - Adds firewall rule instantly
5. **Notification Sent** - Telegram/Email/SMS alert
6. **Auto-Expire** - Removes block after timeout (configurable)

### Platform-Specific Blocking

**Linux:**
```bash
# Uses iptables
sudo iptables -A INPUT -s <IP> -j DROP
```

**Windows:**
```bash
# Uses Windows Firewall
netsh advfirewall firewall add rule name="Block_<IP>" dir=in action=block remoteip=<IP>
```

**macOS:**
```bash
# Uses pfctl
echo 'block drop from <IP> to any' | sudo pfctl -f -
```

### Manual IP Management

**Unblock an IP:**
```python
from alert_manager_enhanced import EnhancedAlertManager
manager = EnhancedAlertManager()
manager.unblock_ip('192.168.1.100')
```

**View Blocked IPs:**
```python
blocked_ips = manager.get_blocked_ips()
print(blocked_ips)
```

---

## 📱 Telegram Alert Examples

When a threat is detected, you'll receive:

```
🔴 SECURITY ALERT: CRITICAL

🕒 Time: 2024-02-09 14:23:45
🔍 Alert ID: alert_1707484425123_42

🌐 Network Details:
• Protocol: TCP
• Source: 203.0.113.42:54321
• Destination: 192.168.1.100:22

📊 Analysis:
• Anomaly Score: -0.6543
• Packet Size: 1024 bytes
• Duration: 2.5 sec

⚠️ Action required! Check dashboard for details.
```

If auto-blocked:
```
🔴 IP ADDRESS BLOCKED!

🚫 Blocked IP: 203.0.113.42
⚠️ Reason: Critical severity - immediate block

📊 Alert Details:
• Severity: CRITICAL
• Protocol: TCP
• Anomaly Score: -0.6543

🔥 Firewall Action: IP has been automatically blocked
⏰ Time: 2024-02-09 14:23:45
```

---

## 📊 Forensic Reports

### Automatic Report Generation

Reports are generated automatically:
- **Daily**: Complete security summary
- **Weekly**: Comprehensive threat analysis
- **On-Demand**: Manual report generation

### Report Contents

```
===============================================================================
AI NETWORK SECURITY GUARD - FORENSIC ANALYSIS REPORT
===============================================================================

Report Generated: 2024-02-09 14:30:00
Time Range: 24h
Total Alerts Analyzed: 127

SEVERITY DISTRIBUTION:
────────────────────────────────────────────────────────────────────────────
  CRITICAL  :    12 (  9.4%)
  HIGH      :    28 ( 22.0%)
  MEDIUM    :    45 ( 35.4%)
  LOW       :    42 ( 33.1%)

TOP 10 ATTACKING IPs:
────────────────────────────────────────────────────────────────────────────
  1. 203.0.113.42         -    15 alerts [BLOCKED]
  2. 198.51.100.23        -    12 alerts [BLOCKED]
  3. 192.0.2.100          -     8 alerts
  ...

PROTOCOL DISTRIBUTION:
────────────────────────────────────────────────────────────────────────────
  TCP       :    89 ( 70.1%)
  UDP       :    23 ( 18.1%)
  ICMP      :    15 ( 11.8%)

DETECTED ATTACK PATTERNS:
────────────────────────────────────────────────────────────────────────────
  • PORT_SCAN: Possible port scan detected (45 different ports)
  • PERSISTENT_ATTACKER: Repeated attacks from 203.0.113.42 (15 alerts)

===============================================================================
```

---

## 🔧 Configuration Guide

### Adjust Auto-Block Sensitivity

```python
# In config_enhanced.py
FIREWALL_CONFIG = {
    # Strict blocking (recommended for production)
    'block_threshold_count': 1,  # Block after 1 alert
    'block_on_severity': ['CRITICAL', 'HIGH'],
    
    # Moderate blocking (balanced)
    'block_threshold_count': 3,  # Block after 3 alerts
    'block_on_severity': ['CRITICAL', 'HIGH'],
    
    # Lenient blocking (testing/learning)
    'block_threshold_count': 10,  # Block after 10 alerts
    'block_on_severity': ['CRITICAL'],
}
```

### Configure Notification Channels

```python
NOTIFICATION_CONFIG = {
    # Telegram - Instant mobile alerts
    'telegram_enabled': True,
    'telegram_on_severity': ['CRITICAL', 'HIGH', 'MEDIUM'],
    
    # Email - Detailed reports
    'email_enabled': True,
    'email_on_severity': ['CRITICAL', 'HIGH'],
    
    # SMS - Critical only (costs money!)
    'sms_enabled': False,
    'sms_on_severity': ['CRITICAL'],
    
    # Slack - Team notifications
    'slack_enabled': False,
    'slack_on_severity': ['CRITICAL', 'HIGH'],
}
```

### Forensic Settings

```python
FORENSIC_CONFIG = {
    'forensic_enabled': True,
    'capture_full_packets': True,
    'pcap_storage_enabled': True,
    'max_pcap_size_mb': 500,
    
    'auto_generate_reports': True,
    'report_interval_hours': 24,
    'report_format': 'both',  # 'txt', 'json', 'both'
    
    'forensic_data_retention_days': 90,
    'compress_old_logs': True,
}
```

---

## 🐛 Troubleshooting

### Firewall Issues

**"Permission denied" when blocking:**
```bash
# Solution: Run with administrator privileges
sudo python packet_sniffer.py  # Linux/Mac
# Or run PowerShell/CMD as Administrator (Windows)
```

**Firewall rules not working:**
```bash
# Check if firewall service is running
# Linux:
sudo systemctl status iptables
# Windows:
netsh advfirewall show currentprofile
```

### Telegram Issues

**Bot not sending messages:**
1. Check bot token is correct
2. Verify chat ID is accurate
3. Test with: `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Ensure bot is not blocked by user

**Finding Chat ID:**
```bash
# Send a message to your bot, then visit:
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
# Look for "chat":{"id": YOUR_CHAT_ID}
```

### Email Issues

**Gmail authentication failed:**
- Use App Password, not regular password
- Enable "Less secure app access" (not recommended)
- Check 2FA is enabled

---

## 📚 Example Scenarios

### Scenario 1: Port Scan Detection

```
🚨 Detection: Port scan from 203.0.113.42
📊 Activity: 45 different ports scanned in 2 minutes
🔥 Action: IP automatically blocked
📱 Alert: Telegram notification sent
📝 Forensic: Full activity logged to PCAP
```

### Scenario 2: DDoS Attack

```
🚨 Detection: 150 connections from 50 unique IPs
📊 Pattern: Distributed Denial of Service attack
🔥 Action: Top 10 attacking IPs blocked
📱 Alert: CRITICAL notifications to all channels
📝 Forensic: Comprehensive attack report generated
```

### Scenario 3: Data Exfiltration

```
🚨 Detection: 25 MB transferred to unknown IP
📊 Analysis: Abnormal outbound traffic pattern
🔥 Action: Destination IP blocked (if repeated)
📱 Alert: HIGH severity notification
📝 Forensic: Full packet capture for investigation
```

---

## 🎓 Security Best Practices

1. **Start with Monitoring** - Run without auto-block first to understand your network
2. **Build Whitelist** - Add all trusted IPs to prevent false positives
3. **Review Reports** - Check forensic reports regularly
4. **Test Notifications** - Verify all alert channels work
5. **Backup Configs** - Save your configuration files
6. **Update Regularly** - Keep Python packages updated
7. **Monitor Resources** - Check CPU/memory usage periodically

---

## 🚀 Advanced Features

### Custom Attack Detection Rules

Create custom detection patterns in `alert_manager_enhanced.py`:

```python
def detect_custom_pattern(self, recent_alerts):
    # Example: Detect cryptocurrency mining
    for alert in recent_alerts:
        if alert['dst_port'] in [3333, 4444, 5555]:  # Mining ports
            return {
                'type': 'CRYPTO_MINING',
                'severity': 'HIGH',
                'description': 'Possible cryptocurrency mining detected'
            }
```

### Integration with SIEM

Export alerts to your SIEM system:

```python
def export_to_siem(alert):
    # Send to Splunk, ELK, QRadar, etc.
    siem_endpoint = "https://your-siem.com/api/alerts"
    requests.post(siem_endpoint, json=alert)
```

---

## 📝 License

This project is for educational and professional security purposes. Use responsibly and ensure you have permission to monitor network traffic.

---

## 🙋 Support & Contribution

### Common Issues

1. **High false positive rate** - Adjust contamination parameter
2. **Missing alerts** - Lower severity thresholds
3. **Too many blocks** - Increase block threshold count
4. **Notifications not sent** - Check API credentials

### Getting Help

1. Check firewall logs: `logs/firewall_blocks.log`
2. Review security alerts: `logs/security_alerts.log`
3. Check forensic data: `forensics/` directory
4. Test Telegram bot: Send `/start` to your bot

---

## 🎉 You're Protected!

You now have an enterprise-grade AI security system that:

✅ Monitors your network 24/7  
✅ Detects unknown/Zero-Day threats  
✅ Automatically blocks attackers  
✅ Sends instant alerts to your phone  
✅ Generates forensic reports  
✅ Learns and adapts to your network  

**Stay safe! 🛡️**
