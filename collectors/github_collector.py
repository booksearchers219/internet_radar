import requests
from event_schema import RadarEvent
from datetime import datetime


def get_github_alerts():

    url = "https://api.github.com/search/repositories?q=security"

    alerts = []

    try:

        r = requests.get(url, timeout=10)

        items = r.json().get("items", [])[:5]

        for repo in items:

            event = RadarEvent(
                title=f"GitHub repo: {repo['name']}",
                source="GitHub",
                type="repository",
                severity=3,
                url=repo["html_url"],
                timestamp=datetime.utcnow().isoformat()
            )

            alerts.append(event.to_dict())

    except Exception as e:

        print("GitHub collector error:", e)

    return alerts