import feedparser

def get_news():

    try:

        feed = feedparser.parse("https://hnrss.org/frontpage")

        alerts = []

        for entry in feed.entries[:5]:

            alerts.append({
                "title": entry.title,
                "url": entry.link,
                "source": "Tech News",
                "severity": 2
            })

        return alerts

    except Exception as e:
        print("RSS collector error:", e)
        return []