import urllib.request
import urllib.error
import json
import time

print("[SIEM] Monitoring network traffic logs...")
time.sleep(2) # Simulating time passing

suspicious_ip = "192.168.1.99"
print(f"[SIEM] ⚠️ ALERT: Anomalous SSH brute-force pattern detected from {suspicious_ip}")
print(f"[SIEM] Forwarding IP to Java SOAR API for autonomous evaluation...\n")

url = "http://localhost:7070/api/analyze"
data = json.dumps({"ip": suspicious_ip}).encode('utf-8')
headers = {'Content-Type': 'application/json'}

req = urllib.request.Request(url, data=data, headers=headers)

try:
    # This automatically triggers your ThreatManager.java without using the UI
    with urllib.request.urlopen(req) as response:
        result = json.loads(response.read().decode('utf-8'))
        print("=== RESPONSE FROM SOAR AI ===")
        print(json.dumps(result, indent=2))
        
        if result.get("severity_level") in ["High", "Critical"]:
            print("\n[SIEM] Confirmed: SOAR successfully blocked the threat.")
            
except urllib.error.URLError as e:
    print(f"[SIEM ERROR] Failed to connect to Java API. Is ThreatManager running? Error: {e}")