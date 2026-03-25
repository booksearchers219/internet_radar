import json
import time
import datetime
from collectors.shodan_change_detector import detect_changes
from collectors.cve_collector import get_cves
from collectors.github_collector import get_github_alerts
from collectors.rss_collector import get_news

DATA_FILE = "data/radar.json"


def score_event(event):

    score = event.get("severity", 1)

    title = event["title"].lower()

    if "critical" in title:
        score += 5

    if "vulnerability" in title:
        score += 3

    if "exploit" in title:
        score += 4

    return score


def collect_data():

    now = datetime.datetime.utcnow().isoformat()

    alerts = []

    print("Running Shodan change detector")
    alerts += detect_changes()

    print("Running CVE collector")
    alerts += get_cves()

    print("Running GitHub collector")
    alerts += get_github_alerts()

    print("Running RSS collector")
    alerts += get_news()

    for alert in alerts:

        alert["score"] = score_event(alert)

        print(f"[{alert['score']}] {alert['title']}")

    alerts.sort(key=lambda x: x["score"], reverse=True)

    radar_data = {
        "last_update": now,
        "alerts": alerts
    }

    with open(DATA_FILE, "w") as f:
        json.dump(radar_data, f, indent=2)

    print("Radar data saved\n")


def main():

    while True:

        print("Collecting radar data...\n")

        collect_data()

        print("Sleeping 600 seconds...\n")

        time.sleep(600)


if __name__ == "__main__":
    main()