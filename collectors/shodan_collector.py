import requests

SHODAN_API_KEY = "E2EiszFxibiTL1lxPo0eUS5P3Wi3KuYa"

def get_shodan_alerts():
    alerts = []

    if not SHODAN_API_KEY:
        return []

    label, query = random.choice(list(SHODAN_PRESETS.items()))

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}"

    try:
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            print("Shodan API error:", r.text)
            return []

        data = r.json()
        matches = data.get("matches", [])[:10]

        for item in matches:
            ip = item.get("ip_str", "Unknown")
            org = item.get("org", "Unknown")
            port = item.get("port", 0)

            explanation = explain_port(port)

            # 🎯 Smart severity logic
            severity = 2
            if port in [3389, 27017]:
                severity = 5  # dangerous
            elif port == 22:
                severity = 4
            elif port == 80:
                severity = 2

            # 🧠 Add learning text
            learning = f"{explanation}. This service is exposed to the internet."

            alerts.append({
                "title": f"{label}: {ip} ({explanation})",
                "url": f"https://www.shodan.io/host/{ip}",
                "source": "Shodan",
                "severity": severity,
                "type": "exposure",
                "learning": learning
            })

    except Exception as e:
        print("Shodan collector error:", e)

    return alerts
