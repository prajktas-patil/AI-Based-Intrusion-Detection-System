"""
Test script to verify anomaly detection is working
Simulates suspicious traffic patterns
"""

import socket
import time
import random

print("🧪 Testing Anomaly Detection System")
print("=" * 50)

# Test 1: Rapid connections (simulates port scan)
print("\n[Test 1] Simulating port scan...")
print("Attempting connections to multiple ports...")

target_host = "google.com"
ports_to_scan = [80, 443, 8080, 3306, 5432, 22, 21, 25, 110, 143]

for port in ports_to_scan:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target_host, port))
        sock.close()
        print(f"  → Port {port}: {'Open' if result == 0 else 'Closed/Filtered'}")
        time.sleep(0.1)  # Small delay
    except Exception as e:
        print(f"  → Port {port}: Error - {e}")

print("\n[Test 2] Generating rapid DNS queries...")
# Rapid DNS lookups
domains = ['google.com', 'facebook.com', 'twitter.com', 'amazon.com', 
           'netflix.com', 'microsoft.com', 'apple.com', 'github.com']

for domain in domains:
    try:
        socket.gethostbyname(domain)
        print(f"  → Resolved: {domain}")
        time.sleep(0.05)
    except:
        pass

print("\n[Test 3] Rapid ping sequence...")
# Multiple pings
import subprocess
for i in range(5):
    subprocess.run(['ping', '-n', '3', 'google.com'], 
                   capture_output=True, timeout=5)
    print(f"  → Ping sequence {i+1}/5")
    time.sleep(0.2)

print("\n" + "=" * 50)
print("✅ Test complete!")
print("Check your monitor terminal for anomaly detections.")
print("Check dashboard for new alerts.")
