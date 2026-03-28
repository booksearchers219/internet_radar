import json
import time
import datetime
import random
from collectors.shodan_change_detector import detect_changes
from collectors.cve_collector import get_cves
from collectors.github_collector import get_github_alerts
from collectors.rss_collector import get_news
from concurrent.futures import ThreadPoolExecutor
from insight_engine import generate_insights
from collectors.shodan_collector import get_shodan_alerts
from correlation_engine import detect_correlations


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
            executor.submit(get_news),
            executor.submit(get_shodan_alerts)  # 👈 ADD THIS LINE
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

    # ✅ STEP 2 — ASSIGN OR REUSE LOCATION (BETTER DEFAULTS)
    final_alerts = []

    for alert in alerts:
        event_id = get_event_id(alert)

        if event_id in existing_map:
            existing = existing_map[event_id]
            alert["lat"] = existing.get("lat")
            alert["lon"] = existing.get("lon")
        else:
            # Better realistic defaults instead of pure random
            title_lower = alert.get("title", "").lower()

            if "russia" in title_lower or "ukraine" in title_lower:
                alert["lat"] = random.uniform(45, 60)
                alert["lon"] = random.uniform(20, 50)
            elif "china" in title_lower:
                alert["lat"] = random.uniform(20, 45)
                alert["lon"] = random.uniform(100, 130)
            elif "us" in title_lower or "america" in title_lower or "microsoft" in title_lower:
                alert["lat"] = random.uniform(30, 50)
                alert["lon"] = random.uniform(-130, -70)
            elif "europe" in title_lower or "github" in title_lower:
                alert["lat"] = random.uniform(40, 55)
                alert["lon"] = random.uniform(-10, 30)
            else:
                # Gentle random for others
                alert["lat"] = random.uniform(-60, 70)
                alert["lon"] = random.uniform(-170, 170)

        final_alerts.append(alert)

    alerts = final_alerts

    # 🔹 Score events
    for alert in alerts:
        alert["score"] = score_event(alert)
        print(f"[{alert['score']}] {alert['title']}")

        if alert.get("learning"):
            print(f"   🧠 {alert['learning']}")

    # 🔹 Sort + limit
    alerts.sort(key=lambda x: x["score"], reverse=True)
    alerts = alerts[:50]

    # 🔹 Generate insights
    insights = generate_insights(alerts)
    correlations = detect_correlations(alerts)

    # 🔹 Save
    radar_data = {
        "last_update": now,
        "alerts": alerts,
        "insights": insights,
        "correlations": correlations
    }

    with open(DATA_FILE, "w") as f:
        json.dump(radar_data, f, indent=2)

    print("Radar data saved\n")

    # 🔥 SHOW INSIGHTS IN TERMINAL
    print("\n" + "=" * 40)
    print("🧠 INSIGHTS ENGINE OUTPUT")
    print("=" * 40 + "\n")
    for i in insights:
        print(i)

    print("\n-----------------------------\n")


def main():
    while True:
        print("Collecting radar data...\n")
        collect_data()
        print("Sleeping 600 seconds...\n")
        time.sleep(600)


if __name__ == "__main__":
    main()
