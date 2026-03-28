import requests
import random
import time
import os
from datetime import datetime

# Load API key from environment variable (set in .bashrc)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")

# Expanded presets (same as before)
SHODAN_PRESETS = {
    "Live Webcams": "webcam has_screenshot:true",
    "RDP Exposed": "port:3389",
    "MongoDB Exposed": "port:27017",
    "Elasticsearch Exposed": "port:9200",
    "Docker Remote API": "port:2375",
    "Telnet Login": 'port:23 "login:"',
    "SSH Servers": "port:22",
    "Industrial Modbus": "port:502",
    "SCADA/ICS Systems": "port:502 OR port:20000 OR port:44818",
    "Vulnerable Services": "vuln:heartbleed OR vuln:ms17-010 OR vuln:cve-",
    "Honeypots": "honeypot:true",
    "Default Passwords": '"admin" OR "password" OR "root"',
    "IoT Devices": "iot OR camera",
}

def explain_port(port):
    explanations = {
        22: "SSH - Remote login (common brute-force target)",
        23: "Telnet - Insecure plain-text access",
        80: "HTTP Web Server",
        443: "HTTPS Web Server",
        3389: "RDP - Remote Desktop (very high risk)",
        27017: "MongoDB - Often unsecured database",
        9200: "Elasticsearch - Frequently exposed with sensitive data",
        2375: "Docker Remote API - Can allow full container takeover",
        502: "Modbus - Industrial control system",
        20000: "DNP3 - SCADA/Industrial protocol",
    }
    return explanations.get(port, f"Service on port {port}")


def get_shodan_alerts():
    alerts = []

    if not SHODAN_API_KEY:
        print("⚠️ SHODAN_API_KEY environment variable is not set.")
        return []

    label, query = random.choice(list(SHODAN_PRESETS.items()))

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}&limit=12"

    try:
        print(f"🔍 Shodan → {label}")

        r = requests.get(url, timeout=15)

        if r.status_code == 429:
            print("Rate limit hit — waiting 3 seconds...")
            time.sleep(3)
            return []

        if r.status_code != 200:
            print(f"Shodan error {r.status_code}")
            return []

        data = r.json()
        matches = data.get("matches", [])[:12]

        for item in matches:
            ip = item.get("ip_str", "Unknown")
            port = item.get("port", 0)
            org = item.get("org", "Unknown Org")
            product = item.get("product") or ""

            explanation = explain_port(port)

            severity = 3
            if port in [3389, 27017, 2375, 23, 502]:
                severity = 5
            elif port == 22 or "vuln" in query.lower() or "honeypot" in query.lower():
                severity = 4
            elif "webcam" in query.lower():
                severity = 4

            title = f"{label}: {ip}"
            if product:
                title += f" — {product}"

            learning = f"{explanation}. Organization: {org}. Publicly reachable right now."

            alerts.append({
                "title": title,
                "url": f"https://www.shodan.io/host/{ip}",
                "source": "Shodan",
                "severity": severity,
                "type": "exposure",
                "learning": learning,
                "timestamp": datetime.utcnow().isoformat(),
                "id": f"shodan-{ip}-{port}-{int(time.time())}",
                "port": port,
                "org": org,
                "product": product
            })

        print(f"✅ Shodan added {len(alerts)} alerts")

    except Exception as e:
        print(f"Shodan error: {e}")

    time.sleep(1.2)
    return alerts