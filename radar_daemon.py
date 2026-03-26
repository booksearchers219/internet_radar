import json
import time
import datetime
import random
from collectors.shodan_change_detector import detect_changes
from collectors.cve_collector import get_cves
from collectors.github_collector import get_github_alerts
from collectors.rss_collector import get_news
from concurrent.futures import ThreadPoolExecutor

DATA_FILE = "data/radar.json"


def get_event_id(event):
    if event.get("id"):
        return event["id"]

    if event.get("url"):
        return event["url"].split("?")[0]

    # LAST RESORT → normalize title
    return event.get("title", "").strip().lower()


def load_existing_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"alerts": []}


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

    # 🔹 Load existing data (STATE)
    existing_data = load_existing_data()
    existing_map = {}

    for e in existing_data.get("alerts", []):
        existing_map[get_event_id(e)] = e

    # 🔹 Collect new data
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(detect_changes),
            executor.submit(get_cves),
            executor.submit(get_github_alerts),
            executor.submit(get_news)
        ]

        for future in futures:
            try:
                result = future.result()
                if result:
                    alerts += result
            except Exception as e:
                print("Collector failed:", e)

    # ✅ STEP 1 — DEDUPE FIRST (by stable ID)
    unique = {}
    for alert in alerts:
        print("ID:", get_event_id(alert), "|", alert["title"])
        key = get_event_id(alert)
        unique[key] = alert

    alerts = list(unique.values())

    # ✅ STEP 2 — ASSIGN OR REUSE LOCATION (ONLY ONCE)
    final_alerts = []

    for alert in alerts:
        event_id = get_event_id(alert)

        if event_id in existing_map:
            existing = existing_map[event_id]
            alert["lat"] = existing.get("lat")
            alert["lon"] = existing.get("lon")
        else:
            alert["lat"] = random.uniform(-70, 70)
            alert["lon"] = random.uniform(-180, 180)

        final_alerts.append(alert)

    alerts = final_alerts

    # 🔹 Score events
    for alert in alerts:
        alert["score"] = score_event(alert)
        print(f"[{alert['score']}] {alert['title']}")

    # 🔹 Sort + limit
    alerts.sort(key=lambda x: x["score"], reverse=True)
    alerts = alerts[:50]

    # 🔹 Save
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