# 🛡️ AI Network Security Guard

An AI-powered network security system that uses **Anomaly Detection** to catch Zero-Day attacks and unknown threats in real-time.

## 🌟 What It Does

Instead of relying on signature-based detection (like a "Most Wanted" list), this system:
- **Learns** what normal network behavior looks like
- **Monitors** your live network traffic in real-time
- **Detects** suspicious activity that deviates from the baseline
- **Alerts** you instantly through a beautiful dashboard

This means it can catch **brand new attacks** that have never been seen before!

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI SECURITY GUARD                        │
└─────────────────────────────────────────────────────────────┘

1. CONFIGURATION (config.py)
   ├── Centralized settings
   ├── Model parameters
   ├── Network settings
   └── Notification configuration

2. TRAINING PHASE (train_model.py)
   ├── Download NSL-KDD dataset
   ├── Extract "normal" network patterns
   ├── Train Isolation Forest AI
   └── Save trained model

3. FEATURE EXTRACTION (feature_extractor.py)
   ├── Advanced packet analysis
   ├── Connection tracking
   ├── Time-based features
   └── Host-based statistics

4. MONITORING PHASE (packet_sniffer.py)
   ├── Capture live packets with PyShark
   ├── Extract network features
   ├── Compare against learned baseline
   └── Flag anomalies

5. ALERT MANAGEMENT (alert_manager.py)
   ├── Alert deduplication
   ├── Attack pattern correlation
   ├── Multi-channel notifications
   └── Risk analysis

6. UTILITIES (utils.py)
   ├── Logging system
   ├── Email/Slack alerts
   ├── Model save/load
   └── Report generation

7. EVALUATION (model_evaluator.py)
   ├── Model performance testing
   ├── Attack type analysis
   ├── Accuracy metrics
   └── Evaluation reports

8. VISUALIZATION (dashboard.py)
   ├── Real-time Streamlit dashboard
   ├── Alert timeline & severity breakdown
   ├── Protocol analysis
   └── Live statistics
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
- **Administrator/Root access** for packet capture
- Network interface access

---

## 🚀 Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Verify TShark Installation

```bash
# Check if tshark is installed
tshark --version
```

If not found, install Wireshark (includes TShark).

---

## 💻 Usage

### Phase 1: Train the AI Brain 🧠

First, train the model to learn what "normal" network traffic looks like:

```bash
python train_model.py
```

**What happens:**
- Downloads NSL-KDD dataset (~5MB)
- Analyzes thousands of normal network connections
- Trains Isolation Forest model
- Saves model to disk

**Output files:**
- `anomaly_model.pkl` - Trained AI model
- `scaler.pkl` - Feature normalization
- `features.pkl` - Feature list

**Duration:** 2-5 minutes

---

### Phase 2: Monitor Network (Option A - Command Line) 👁️

Run the packet sniffer to monitor your network:

```bash
# Windows (Run as Administrator)
python packet_sniffer.py

# Linux/Mac (Run with sudo)
sudo python packet_sniffer.py
```

**Important:** Change the network interface in `packet_sniffer.py`:
```python
interface = 'Wi-Fi'  # Change to your interface name
```

**Finding your interface:**
- Windows: `ipconfig` → Look for your active adapter
- Mac: `ifconfig` → Usually `en0` or `en1`
- Linux: `ip addr` → Usually `eth0` or `wlan0`

---

### Phase 3: Launch Dashboard (Option B - Visual) 📊

For a beautiful real-time visualization:

```bash
# Windows (Run as Administrator)
streamlit run dashboard.py

# Linux/Mac (Run with sudo)
sudo streamlit run dashboard.py
```

**Dashboard features:**
- 🚨 Real-time anomaly alerts
- 📈 Severity breakdown (Critical/High/Medium/Low)
- 🌐 Protocol distribution
- ⏱️ Alert timeline
- 📊 Live statistics

**Access:** Opens automatically at `http://localhost:8501`

---

## 🎯 How It Works

### 1. Learning Phase
```python
Normal Traffic Pattern → Isolation Forest → Learned Baseline
```

The AI studies features like:
- Packet duration
- Source/destination bytes
- Connection counts
- Error rates
- Service patterns

### 2. Detection Phase
```python
Live Packet → Feature Extraction → Compare to Baseline → Anomaly Score
```

If the score indicates deviation from normal:
- ✅ **Score > -0.1**: Normal traffic
- ⚠️ **Score -0.1 to -0.3**: Low/Medium severity
- 🚨 **Score < -0.5**: Critical anomaly!

### 3. Alert Classification

| Severity | Score Range | Meaning |
|----------|-------------|---------|
| 🟢 LOW | -0.1 to 0 | Slight deviation |
| 🟡 MEDIUM | -0.3 to -0.1 | Notable anomaly |
| 🟠 HIGH | -0.5 to -0.3 | Serious threat |
| 🔴 CRITICAL | < -0.5 | Immediate action |

---

## 📊 Understanding the Output

### Command Line Output:
```
👁️  Starting network monitoring on Wi-Fi...
🔍 Press Ctrl+C to stop

📊 Analyzed: 10 packets | 🚨 Anomalies: 0
📊 Analyzed: 20 packets | 🚨 Anomalies: 1

🚨 ANOMALY DETECTED!
   Time: 14:23:45
   Protocol: TCP
   Source: 192.168.1.105
   Destination: 203.0.113.42
   Severity: HIGH
   Score: -0.42
```

### Dashboard Display:
- **Alert Table**: Recent anomalies with full details
- **Severity Pie Chart**: Distribution of threat levels
- **Protocol Bar Chart**: Which protocols are suspicious
- **Timeline Graph**: When anomalies occurred

---

## 🔧 Customization

### Adjust Sensitivity

In `train_model.py`, modify contamination:
```python
model = IsolationForest(
    contamination=0.01,  # 1% expected anomalies (strict)
    # contamination=0.05  # 5% (more lenient)
)
```

### Monitor Specific Ports

In `packet_sniffer.py`:
```python
capture = pyshark.LiveCapture(
    interface=self.interface,
    bpf_filter='port 80 or port 443'  # Only HTTP/HTTPS
)
```

### Change Alert Thresholds

In `packet_sniffer.py`:
```python
def _calculate_severity(self, score):
    if score < -0.4:  # Adjust these thresholds
        return 'CRITICAL'
    elif score < -0.2:
        return 'HIGH'
    # ...
```

---

## 🐛 Troubleshooting

### "Permission Denied" Error
**Solution:** Run with administrator/sudo privileges

### "Interface not found"
**Solution:** 
1. List available interfaces: `tshark -D`
2. Update interface name in code

### "Model not found"
**Solution:** Run `train_model.py` first

### PyShark not capturing packets
**Solution:**
1. Verify TShark installation: `tshark --version`
2. Check firewall settings
3. Ensure interface is active

### Dashboard not showing alerts
**Solution:** 
1. Enable "Demo Mode" to test visualization
2. Check if model files exist
3. Verify network traffic is flowing

---

## 🎓 What Makes This Special?

### Traditional Security (Signature-Based)
- ❌ Needs to know the attack beforehand
- ❌ Can't catch new/unknown threats
- ❌ Constantly needs updates

### This AI System (Anomaly-Based)
- ✅ Learns normal behavior automatically
- ✅ Detects unknown/Zero-Day attacks
- ✅ Adapts to your network patterns

---

## 📚 Technical Details

### Model: Isolation Forest
- **Type:** Unsupervised anomaly detection
- **How it works:** Isolates anomalies by random partitioning
- **Why it's good:** Fast, effective for high-dimensional data

### Dataset: NSL-KDD
- **Purpose:** Network intrusion detection benchmark
- **Size:** ~125,000 connections
- **Labels:** Normal + various attack types

### Features Used:
- Duration, byte counts, connection counts
- Error rates, service patterns
- Host-based statistics

---

## 🚀 Future Enhancements

Want to make it even better? Consider:
- **Deep Learning**: Use LSTM/Autoencoders for sequence analysis
- **Multi-stage Detection**: Combine with signature-based detection
- **Automatic Response**: Block suspicious IPs automatically
- **Cloud Integration**: Send alerts to Slack/email
- **Historical Analysis**: Store and analyze long-term patterns

---

## 📝 License

This project is for educational purposes. Use responsibly and ensure you have permission to monitor network traffic.

---

## 🙋 Support

Having issues? Common fixes:
1. Always run with admin/sudo privileges
2. Ensure TShark is installed
3. Train the model before monitoring
4. Check your network interface name

---

## 🎉 You Did It!

You now have an AI-powered security guard watching your network 24/7, catching threats that traditional systems would miss!

**Next Steps:**
1. Train the model: `python train_model.py`
2. Start monitoring: `streamlit run dashboard.py`
3. Watch the alerts roll in! 🛡️
