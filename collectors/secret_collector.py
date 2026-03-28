import requests

def get_secret_alerts():
    url = "https://api.github.com/search/code?q=AWS_SECRET_ACCESS_KEY"

    alerts = []

    try:
        r = requests.get(url, timeout=10)
        items = r.json().get("items", [])[:5]

        for item in items:
            alerts.append({
                "title": f"Possible AWS secret leak: {item.get('name', 'unknown')}",
                "url": item.get("html_url", ""),
                "source": "GitHub Leak",
                "severity": 5
            })

    except Exception as e:
        print("Secret collector error:", e)

    return alerts