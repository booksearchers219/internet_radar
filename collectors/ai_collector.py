import requests

def get_ai_alerts():

    url = "https://huggingface.co/api/models?sort=downloads&limit=5"

    alerts = []

    try:

        r = requests.get(url, timeout=10)

        models = r.json()

        for model in models:

            alerts.append({
                "title": f"AI model trending: {model['id']}",
                "url": f"https://huggingface.co/{model['id']}",
                "source": "AI",
                "severity": 3
            })

    except Exception as e:
        print("AI collector error:", e)

    return alerts
