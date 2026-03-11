# 🚀 Quick Start Guide - AI Network Security Guard

This guide will get you up and running in minutes!

## 📋 Step-by-Step Installation

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

**If you get errors, try:**
```bash
python -m pip install --upgrade pip
pip install pandas numpy scikit-learn pyshark streamlit plotly matplotlib requests
```

### Step 2: Install Wireshark/TShark

**Windows:**
1. Download from: https://www.wireshark.org/download.html
2. Run installer
3. **Important:** Check "Install TShark" during installation
4. Restart your computer

**Mac:**
```bash
brew install wireshark
```

**Linux:**
```bash
sudo apt-get update
sudo apt-get install tshark
```

### Step 3: Verify Installation

```bash
# Check Python packages
python -c "import pandas, numpy, sklearn, pyshark, streamlit"

# Check TShark
tshark --version
```

---

## ⚙️ Configuration (Optional)

Before running, you can customize settings in `config.py`:

```python
# Change network interface
NETWORK_CONFIG = {
    'default_interface': 'Wi-Fi',  # Change to your interface
}

# Adjust sensitivity
MODEL_CONFIG = {
    'contamination': 0.01,  # 1% = strict, 5% = lenient
}

# Enable email alerts
NOTIFICATION_CONFIG = {
    'email_enabled': True,
    'email_sender': 'your_email@gmail.com',
    'email_password': 'your_app_password',
    'email_recipients': ['admin@company.com'],
}
```

---

## 🎯 Quick Start - 3 Commands

### 1️⃣ Train the AI (One-time setup)

```bash
python train_model.py
```

**Expected output:**
```
🛡️  AI Network Security Guard - Training Phase
📥 Downloading NSL-KDD dataset...
✅ Dataset downloaded!
🔄 Loading and preprocessing data...
📊 Found 67343 normal connections to learn from
🧠 Training AI to learn normal behavior...
✅ Model trained successfully!
💾 Saving model...
✅ Model saved! Ready for real-time detection.
```

**Time:** 2-5 minutes  
**Files created:** `anomaly_model.pkl`, `scaler.pkl`, `features.pkl`

---

### 2️⃣ (Optional) Evaluate Model Performance

```bash
python model_evaluator.py
```

This tests your model and shows:
- Detection accuracy
- False positive rate
- Performance by attack type

---

### 3️⃣ Launch Dashboard

```bash
# Windows (Run as Administrator in PowerShell)
streamlit run dashboard.py

# Mac/Linux
sudo streamlit run dashboard.py
```

**Your browser will open automatically at:** `http://localhost:8501`

---

## 🎭 Testing Without Live Network

If you want to see the dashboard in action without capturing real traffic:

1. Launch dashboard: `streamlit run dashboard.py`
2. Check "🎭 Demo Mode"
3. Click "Generate Demo Alert"
4. Watch simulated alerts appear!

---

## 🔧 Finding Your Network Interface

### Windows:
```cmd
ipconfig
```
Look for: `Wireless LAN adapter Wi-Fi` or `Ethernet adapter Ethernet`  
Use: `Wi-Fi` or `Ethernet`

### Mac:
```bash
ifconfig
```
Look for: `en0`, `en1`  
Use: `en0` or `en1`

### Linux:
```bash
ip addr
```
Look for: `eth0`, `wlan0`  
Use: `eth0` or `wlan0`

Update in `config.py`:
```python
NETWORK_CONFIG = {
    'default_interface': 'YOUR_INTERFACE_HERE',
}
```

---

## 🚨 Common Issues & Fixes

### Issue 1: "Permission Denied"
**Solution:**
```bash
# Windows: Run as Administrator
# Mac/Linux: Use sudo
sudo streamlit run dashboard.py
```

### Issue 2: "Module not found: plotly"
**Solution:**
```bash
pip install plotly
```

### Issue 3: "TShark not found"
**Solution:**
- Install Wireshark (includes TShark)
- Restart computer
- Verify: `tshark --version`

### Issue 4: "Model not found"
**Solution:**
```bash
# Train the model first
python train_model.py
```

### Issue 5: Can't see packets
**Solution:**
1. Check interface name is correct
2. Make sure network is active
3. Try demo mode first
4. Check firewall settings

---

## 📊 Understanding the Dashboard

### Status Indicators:
- 🟢 **MONITORING** - Actively capturing packets
- ⚪ **STANDBY** - Ready but not capturing

### Alert Severity:
- 🔴 **CRITICAL** - Immediate action required
- 🟠 **HIGH** - High priority threat
- 🟡 **MEDIUM** - Monitor closely
- 🟢 **LOW** - Low priority

### Charts:
1. **Severity Pie Chart** - Distribution of alert types
2. **Protocol Bar Chart** - Which protocols are suspicious
3. **Timeline Graph** - When alerts occurred

---

## 🎓 Usage Examples

### Example 1: Basic Monitoring
```bash
python train_model.py          # One-time training
streamlit run dashboard.py      # Start monitoring
```

### Example 2: Command-Line Monitoring
```bash
python train_model.py          # One-time training
python packet_sniffer.py       # Monitor in terminal
```

### Example 3: Full Setup with Evaluation
```bash
python train_model.py          # Train model
python model_evaluator.py      # Test performance
streamlit run dashboard.py      # Start dashboard
```

---

## 🔔 Setting Up Notifications

### Email Alerts (Gmail):

1. Generate App Password:
   - Go to: https://myaccount.google.com/apppasswords
   - Generate password for "Mail"

2. Update `config.py`:
```python
NOTIFICATION_CONFIG = {
    'email_enabled': True,
    'email_sender': 'your_email@gmail.com',
    'email_password': 'your_16_char_app_password',
    'email_recipients': ['admin@company.com'],
    'email_on_severity': ['CRITICAL', 'HIGH'],
}
```

### Slack Alerts:

1. Create Incoming Webhook:
   - Go to: https://api.slack.com/messaging/webhooks
   - Create webhook for your channel

2. Update `config.py`:
```python
NOTIFICATION_CONFIG = {
    'slack_enabled': True,
    'slack_webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
    'slack_on_severity': ['CRITICAL', 'HIGH'],
}
```

---

## 📈 Performance Tips

1. **Faster Training:**
   - Use smaller sample size in config
   - Reduce n_estimators

2. **Reduce False Positives:**
   - Increase contamination parameter
   - Adjust severity thresholds

3. **Better Detection:**
   - Collect more training data
   - Adjust feature selection

---

## 🛠️ File Structure

```
project/
├── config.py              # All configuration
├── train_model.py         # AI training
├── feature_extractor.py   # Feature extraction
├── packet_sniffer.py      # Packet capture
├── alert_manager.py       # Alert handling
├── utils.py               # Helper functions
├── model_evaluator.py     # Model testing
├── dashboard.py           # Web dashboard
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```

**Generated Files:**
```
├── anomaly_model.pkl      # Trained model
├── scaler.pkl             # Feature scaler
├── features.pkl           # Feature list
├── KDDTrain.txt          # Training dataset
└── logs/                  # Log files
    └── security_alerts.log
```

---

## ✅ Verification Checklist

- [ ] Python 3.8+ installed
- [ ] All packages installed (`pip install -r requirements.txt`)
- [ ] TShark/Wireshark installed
- [ ] Model trained (`train_model.py`)
- [ ] Network interface configured
- [ ] Dashboard launches successfully
- [ ] Demo mode works

---

## 🎉 You're Ready!

Your AI Network Security Guard is now protecting your network!

**Next Steps:**
1. Monitor the dashboard for alerts
2. Review attack patterns in the statistics
3. Set up email/Slack notifications
4. Generate reports for analysis

**Need Help?**
- Check the main README.md for detailed explanations
- Review logs in `logs/network_guard.log`
- Test with demo mode first

---

**Happy Monitoring! 🛡️**
