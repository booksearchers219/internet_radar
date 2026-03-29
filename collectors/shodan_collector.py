import os
import random
import time
from datetime import datetime
import shodan  # Official library

# Load API key from environment
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "").strip()

if not SHODAN_API_KEY:
    print("❌ ERROR: SHODAN_API_KEY environment variable is not set!")
    SHODAN_API = None
else:
    SHODAN_API = shodan.Shodan(SHODAN_API_KEY)
    print("✅ Shodan official library initialized successfully")

# Rich presets for interesting discoveries (counts are cheap, details are expensive)
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
        print("⚠️ Shodan API not available (missing key)")
        return []

    alerts = []

    try:
        # First, show overview counts for all presets (this is very cheap / often free)
        print("🔍 Shodan → Getting overview counts for exposed services...")
        for label, query in list(SHODAN_PRESETS.items())[:8]:  # Limit to first 8 to keep it fast
            try:
                count_result = SHODAN_API.count(query)
                total = count_result.get('total', 0)
                print(f"   {label}: {total:,} hosts")
            except Exception:
                pass  # Don't fail the whole collector on one bad count

        # Now pick ONE interesting category for detailed alerts (this is the part that can cost credits)
        label, query = random.choice(list(SHODAN_PRESETS.items()))
        print(f"\n🔍 Shodan → Detailed scan: {label}")

        # Try to get count first
        try:
            count_result = SHODAN_API.count(query)
            total = count_result.get('total', 0)
            print(f"   Total matching hosts: {total:,}")
        except Exception as e:
            print(f"   Could not get count: {e}")
            total = 0

        # Only do actual search (costs credits) if we have a reasonable number of results
        if total == 0:
            print("   No hosts found for this query.")
            return alerts

        # Fetch a small number of recent/exposed hosts (limit=10 is safe)
        results = SHODAN_API.search(query, limit=10)

        added = 0
        for item in results.get('matches', [])[:10]:
            ip = item.get('ip_str', 'Unknown')
            port = item.get('port', 0)
            org = item.get('org', 'Unknown Org')
            product = item.get('product') or item.get('_shodan', {}).get('module', '')

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
            added += 1

        print(f"✅ Shodan added {added} detailed alerts from {label}")

    except shodan.APIError as e:
        error_str = str(e).lower()
        if "insufficient query credits" in error_str or "credit" in error_str:
            print("❌ Shodan API Error: Insufficient query credits.")
            print("   Consider upgrading your plan or waiting for monthly reset.")
            print("   (Counts still worked — only detailed search was skipped)")
        else:
            print(f"❌ Shodan API Error: {e}")
    except Exception as e:
        print(f"❌ Shodan error: {e}")

    # Small delay to be respectful
    time.sleep(1.5)
    return alerts