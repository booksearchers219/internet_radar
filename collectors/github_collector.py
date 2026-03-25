import requests

def get_github_alerts():

    url = "https://api.github.com/search/repositories?q=security"

    try:

        r = requests.get(url, timeout=10)

        items = r.json().get("items", [])[:5]

        alerts = []

        for repo in items:

            alerts.append({
                "title": f"GitHub repo: {repo['name']}",
                "url": repo["html_url"],
                "source": "GitHub",
                "severity": 3
            })

        return alerts

    except Exception as e:
        print("GitHub collector error:", e)
        return []