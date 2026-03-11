# 🚀 Quick Setup Guide - Enhanced Features

## 5-Minute Setup for Telegram Alerts + Auto-Blocking

### Step 1: Get Telegram Bot Token (2 minutes)

1. Open Telegram on your phone
2. Search for `@BotFather`
3. Send: `/newbot`
4. Choose a name: `My Security Guard Bot`
5. Choose username: `my_security_guard_bot`
6. **COPY THE TOKEN** (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### Step 2: Get Your Chat ID (1 minute)

1. Search for `@userinfobot`
2. Send: `/start`
3. **COPY YOUR CHAT ID** (number like: `987654321`)

### Step 3: Configure the System (2 minutes)

Open `config_enhanced.py` and update:

```python
# Line ~155: Enable Telegram
'telegram_enabled': True,
'telegram_bot_token': '123456789:ABCdefGHIjklMNOpqrsTUVwxyz',  # YOUR TOKEN
'telegram_chat_ids': ['987654321'],  # YOUR CHAT ID

# Line ~120: Enable Auto-Block
'auto_block_enabled': True,
'block_threshold_count': 3,  # Block after 3 suspicious alerts
'block_on_severity': ['CRITICAL', 'HIGH'],

# Line ~143: Add your network to whitelist
'whitelist_ips': [
    '127.0.0.1',
    '192.168.1.1',     # Your router
    '192.168.1.100',   # Your computer (find with ipconfig/ifconfig)
],
```

### Step 4: Run the System

```bash
# Install dependencies
pip install -r requirements_enhanced.txt

# Train the AI model (one-time)
python train_model.py

# Start monitoring (requires admin/sudo)
sudo streamlit run dashboard.py
```

### Step 5: Test It!

You should receive a Telegram message when the system detects anomalies!

---

## 📧 Email Setup (Gmail)

### Create App Password

1. Go to: https://myaccount.google.com/security
2. Enable **2-Step Verification** (if not already)
3. Go to: https://myaccount.google.com/apppasswords
4. Select app: `Mail`
5. Select device: `Other (Custom name)` → Type: `Security Guard`
6. Click **Generate**
7. **COPY THE 16-CHARACTER PASSWORD**

### Configure Email

```python
# In config_enhanced.py
'email_enabled': True,
'email_smtp_server': 'smtp.gmail.com',
'email_smtp_port': 587,
'email_sender': 'your.email@gmail.com',
'email_password': 'abcd efgh ijkl mnop',  # App password (no spaces in config)
'email_recipients': ['admin@company.com', 'security@company.com'],
```

---

## 🔥 Firewall Configuration

### Windows Setup

1. Run PowerShell as Administrator
2. Ensure Windows Firewall is enabled:
   ```powershell
   Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True
   ```

### Linux Setup

1. Install iptables (if not installed):
   ```bash
   sudo apt-get install iptables
   sudo systemctl enable iptables
   ```

2. Save rules automatically:
   ```bash
   sudo apt-get install iptables-persistent
   ```

### macOS Setup

1. Enable firewall:
   ```bash
   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
   ```

2. pfctl is built-in, no additional setup needed

---

## 🧪 Testing Your Setup

### Test 1: Verify Telegram Bot

```python
# test_telegram.py
import requests

BOT_TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"

url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
message = "🛡️ Security Guard is online!"

response = requests.post(url, json={
    'chat_id': CHAT_ID,
    'text': message
})

print("✅ Success!" if response.status_code == 200 else f"❌ Failed: {response.text}")
```

Run: `python test_telegram.py`

### Test 2: Check Firewall Access

**Linux/Mac:**
```bash
# Check if you have iptables access
sudo iptables -L | head -n 5

# Expected: List of firewall chains (no errors)
```

**Windows:**
```powershell
# Check if you have firewall access (run as Admin)
netsh advfirewall show allprofiles

# Expected: Firewall status display (no access denied)
```

### Test 3: Generate Test Alert

```python
# test_alert.py
from alert_manager_enhanced import EnhancedAlertManager

manager = EnhancedAlertManager()

test_alert = {
    'id': 'test_001',
    'timestamp': '2024-02-09 12:00:00',
    'severity': 'HIGH',
    'protocol': 'TCP',
    'src_ip': '203.0.113.42',
    'dst_ip': '192.168.1.100',
    'src_port': 54321,
    'dst_port': 22,
    'anomaly_score': -0.45,
    'packet_size': 1024,
    'duration': 2.5,
}

manager.add_alert(test_alert)
print("✅ Test alert sent! Check your Telegram!")
```

---

## 🎯 Configuration Examples

### Scenario 1: Home Network (Lenient)

```python
FIREWALL_CONFIG = {
    'auto_block_enabled': True,
    'block_threshold_count': 10,  # More tolerant
    'block_on_severity': ['CRITICAL'],  # Only critical threats
    'block_duration_minutes': 30,  # Shorter blocks
}

NOTIFICATION_CONFIG = {
    'telegram_enabled': True,
    'telegram_on_severity': ['CRITICAL', 'HIGH'],  # Only important ones
    'email_enabled': False,  # No email spam
}
```

### Scenario 2: Small Business (Balanced)

```python
FIREWALL_CONFIG = {
    'auto_block_enabled': True,
    'block_threshold_count': 3,
    'block_on_severity': ['CRITICAL', 'HIGH'],
    'block_duration_minutes': 60,
}

NOTIFICATION_CONFIG = {
    'telegram_enabled': True,
    'telegram_on_severity': ['CRITICAL', 'HIGH', 'MEDIUM'],
    'email_enabled': True,
    'email_on_severity': ['CRITICAL', 'HIGH'],
    'slack_enabled': True,  # For team
    'slack_on_severity': ['CRITICAL'],
}
```

### Scenario 3: Enterprise (Strict)

```python
FIREWALL_CONFIG = {
    'auto_block_enabled': True,
    'block_threshold_count': 1,  # Block immediately
    'block_on_severity': ['CRITICAL', 'HIGH'],
    'permanent_block_on_critical': True,  # Never auto-unblock critical
}

NOTIFICATION_CONFIG = {
    'telegram_enabled': True,
    'telegram_on_severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],  # All alerts
    'email_enabled': True,
    'email_on_severity': ['CRITICAL', 'HIGH'],
    'sms_enabled': True,
    'sms_on_severity': ['CRITICAL'],
    'slack_enabled': True,
    'slack_on_severity': ['CRITICAL', 'HIGH'],
}

FORENSIC_CONFIG = {
    'forensic_enabled': True,
    'capture_full_packets': True,
    'pcap_storage_enabled': True,
    'auto_generate_reports': True,
    'report_interval_hours': 1,  # Hourly reports
}
```

---

## 📱 Telegram Commands Reference

Once your bot is running, you can interact with it:

**Basic Commands:**
- `/start` - Activate the bot
- `/status` - Get current security status
- `/stats` - View alert statistics
- `/blocked` - List blocked IPs
- `/help` - Show available commands

**Note:** You'll need to implement these commands in a separate Telegram bot handler if you want interactive features.

---

## 🔍 Finding Your Network Interface

### Windows
```bash
ipconfig
# Look for "Wireless LAN adapter" or "Ethernet adapter"
# Interface name is like: "Wi-Fi" or "Ethernet"
```

### Linux
```bash
ip addr
# or
ifconfig
# Look for: eth0, wlan0, enp0s3, etc.
```

### macOS
```bash
ifconfig
# Usually: en0 (Ethernet) or en1 (Wi-Fi)
```

**Update in code:**
```python
# In config_enhanced.py
NETWORK_CONFIG = {
    'default_interface': 'Wi-Fi',  # Change to your interface
}
```

---

## 🐛 Common Setup Issues

### Issue 1: Telegram Bot Not Responding

**Symptoms:** No messages received  
**Solutions:**
1. Verify bot token is correct
2. Check chat ID is accurate
3. Send `/start` to the bot first
4. Test with curl:
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=test"
   ```

### Issue 2: Firewall Blocking Fails

**Symptoms:** Error messages when trying to block IPs  
**Solutions:**
1. Run with administrator/sudo privileges
2. Check firewall service is running
3. Verify permissions:
   ```bash
   # Linux
   sudo iptables -L
   
   # Windows (as Admin)
   netsh advfirewall show currentprofile
   ```

### Issue 3: Email Not Sending

**Symptoms:** Email alerts not received  
**Solutions:**
1. Use App Password, not regular password
2. Check spam folder
3. Verify SMTP settings
4. Test with simple script:
   ```python
   import smtplib
   server = smtplib.SMTP('smtp.gmail.com', 587)
   server.starttls()
   server.login('your@email.com', 'app_password')
   server.quit()
   print("✅ Email config works!")
   ```

### Issue 4: Permission Denied

**Symptoms:** Can't capture packets or modify firewall  
**Solutions:**
- **Linux/Mac:** Always use `sudo`
- **Windows:** Run as Administrator
- Check TShark installation:
  ```bash
  tshark --version
  ```

---

## 📊 Monitoring Tips

### Check Logs
```bash
# Alert log
tail -f logs/security_alerts.log

# Firewall blocks
tail -f logs/firewall_blocks.log

# Application log
tail -f logs/network_guard.log
```

### View Statistics
```python
from alert_manager_enhanced import EnhancedAlertManager

manager = EnhancedAlertManager()
stats = manager.get_statistics()

print(f"Total Alerts: {stats['total_alerts']}")
print(f"Blocked IPs: {stats['blocked_ips']}")
print(f"Notifications Sent: {stats['notifications_sent']}")
```

### Generate Report
```python
from utils_enhanced import generate_forensic_report

alerts = manager.get_recent_alerts(100)
report_file = generate_forensic_report(alerts, time_range='24h')
print(f"Report saved to: {report_file}")
```

---

## ✅ Setup Checklist

- [ ] Python 3.8+ installed
- [ ] TShark/Wireshark installed
- [ ] Dependencies installed (`pip install -r requirements_enhanced.txt`)
- [ ] Telegram bot created and token obtained
- [ ] Chat ID retrieved
- [ ] `config_enhanced.py` updated with credentials
- [ ] Whitelist IPs added
- [ ] Network interface configured
- [ ] Firewall access verified (admin/sudo)
- [ ] Model trained (`python train_model.py`)
- [ ] Test alert sent successfully
- [ ] Dashboard accessible (`streamlit run dashboard.py`)
- [ ] Telegram notifications working
- [ ] Email notifications working (if enabled)
- [ ] Auto-blocking tested

---

## 🎉 You're All Set!

Your enhanced security system is now:
- ✅ Monitoring network traffic
- ✅ Detecting threats with AI
- ✅ Sending instant Telegram alerts
- ✅ Auto-blocking malicious IPs
- ✅ Generating forensic reports

**Next Steps:**
1. Monitor the dashboard for a few hours
2. Review first forensic report
3. Adjust thresholds if needed
4. Add more trusted IPs to whitelist
5. Set up additional notification channels

**Need help?** Check logs in `logs/` directory or review `README_ENHANCED.md`

Stay protected! 🛡️
