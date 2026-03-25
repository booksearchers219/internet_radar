import requests

SHODAN_API_KEY = "YOUR_API_KEY"

def get_shodan_alerts():

    query = "port:27017"

    url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={query}"

    alerts = []

    try:

        r = requests.get(url, timeout=10)

        data = r.json()

        count = data.get("total", 0)

        alerts.append({
            "title": f"Exposed MongoDB servers detected: {count}",
            "url": f"https://www.shodan.io/search?query={query}",
            "source": "Shodan",
            "severity": 4
        })

    except Exception as e:
        print("Shodan collector error:", e)

    return alerts
