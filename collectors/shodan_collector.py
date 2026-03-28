import os
import random
import time
from datetime import datetime
import shodan   # Official library

# Load API key from environment (your .bashrc)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "").strip()

if not SHODAN_API_KEY:
    print("❌ ERROR: SHODAN_API_KEY environment variable is not set!")
    SHODAN_API = None
else:
    SHODAN_API = shodan.Shodan(SHODAN_API_KEY)
    print("✅ Shodan official library initialized successfully")

# Rich presets for interesting discoveries
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
    "IoT Devices": "iot OR camera",
}

def explain_port(port):
    explanations = {
        22: "SSH - Remote login (brute-force target)",
        23: "Telnet - Insecure plain-text access",
        3389: "RDP - Remote Desktop (very high risk)",
        27017: "MongoDB - Often unsecured database",
        9200: "Elasticsearch - Frequently exposed with sensitive data",
        2375: "Docker Remote API - Can allow container takeover",
        502: "Modbus - Industrial control system",
        20000: "DNP3 - SCADA/Industrial protocol",
    }
    return explanations.get(port, f"Service on port {port}")


def get_shodan_alerts():
    if not SHODAN_API:
        return []

    alerts = []
    label, query = random.choice(list(SHODAN_PRESETS.items()))

    try:
        print(f"🔍 Shodan → {label}")

        results = SHODAN_API.search(query, limit=12)

        for item in results.get('matches', [])[:12]:
            ip = item.get('ip_str', 'Unknown')
            port = item.get('port', 0)
            org = item.get('org', 'Unknown Org')
            product = item.get('product', '') or item.get('_shodan', {}).get('module', '')

            explanation = explain_port(port)

            # Severity logic
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

    except shodan.APIError as e:
        print(f"Shodan API Error: {e}")
    except Exception as e:
        print(f"Shodan error: {e}")

    time.sleep(1.2)  # Respect rate limits
    return alerts