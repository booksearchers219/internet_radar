import feedparser
from event_schema import RadarEvent
from datetime import datetime


def get_news():

    alerts = []

    try:

        feed = feedparser.parse("https://hnrss.org/frontpage")

        for entry in feed.entries[:5]:
            event = RadarEvent(
                id=entry.link.split("?")[0],  # ✅ stable ID
                title=entry.title.strip(),
                source="Tech News",
                type="news",
                severity=2,
                url=entry.link.split("?")[0],
                timestamp=datetime.utcnow().isoformat()
            )

            alerts.append(event.to_dict())

    except Exception as e:
        print("RSS collector error:", e)

    return alerts