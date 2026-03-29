import json
import time
import datetime
import random
import sys
import os

from collectors.shodan_change_detector import detect_changes
from collectors.cve_collector import get_cves
from collectors.github_collector import get_github_alerts
from collectors.rss_collector import get_news
from collectors.shodan_collector import get_shodan_alerts
from concurrent.futures import ThreadPoolExecutor

from insight_engine import generate_insights
from correlation_engine import detect_correlations

# ========================= CONFIG =========================
DATA_FILE = "data/radar.json"
POLL_INTERVAL_SECONDS = 86400  # 24 hours - change if you want (e.g. 43200 for 12h)

# Optional: Set to False if you want to skip Shodan entirely on low credits
ALLOW_SHODAN = True


# =========================================================

def get_event_id(event):
    if event.get("id"):
        return event["id"]
    if event.get("url"):
        return event["url"].split("?")[0]
    return event.get("title", "").strip().lower()


def load_existing_data():
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"alerts": []}


def score_event(event):
    score = event.get("severity", 1)
    title = event.get("title", "").lower()

    if "critical" in title:
        score += 5
    if "vulnerability" in title:
        score += 3
    if "exploit" in title:
        score += 4
    return score


def check_shodan_credits():
    """Check remaining Shodan credits and warn if low."""
    try:
        import shodan
        api = shodan.Shodan(os.getenv("SHODAN_API_KEY") or "YOUR_KEY_HERE")  # Better to use env var
        info = api.info()
        credits = info.get("query_credits", 0)
        plan = info.get("plan", "unknown")
        print(f"🔑 Shodan Plan: {plan} | Query credits remaining: {credits}")
        if credits < 20:
            print("⚠️  WARNING: Very low Shodan query credits!")
        return credits > 5
    except Exception as e:
        print(f"⚠️ Could not check Shodan credits: {e}")
        return False


def collect_data():
    now = datetime.datetime.utcnow().isoformat()
    alerts = []

    print("Loading existing radar data...")
    existing_data = load_existing_data()
    existing_map = {get_event_id(e): e for e in existing_data.get("alerts", [])}

    print("Collecting data from sources...")

    # Prepare collectors
    futures = [
        ("change_detector", detect_changes),
        ("cve_collector", get_cves),
        ("github_collector", get_github_alerts),
        ("news_collector", get_news),
    ]

    if ALLOW_SHODAN:
        futures.append(("shodan_collector", get_shodan_alerts))

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(func): name for name, func in futures}

        for future in future_map:
            name = future_map[future]
            try:
                result = future.result(timeout=120)  # Prevent hanging
                if result:
                    alerts.extend(result)
                    print(f"✅ {name} → {len(result)} alerts")
            except Exception as e:
                print(f"❌ {name} failed: {e}")

    # Deduplicate by stable ID
    unique = {}
    for alert in alerts:
        key = get_event_id(alert)
        if key not in unique:
            unique[key] = alert

    alerts = list(unique.values())

    # Add locations (your existing logic)
    final_alerts = []
    for alert in alerts:
        event_id = get_event_id(alert)
        if event_id in existing_map:
            existing = existing_map[event_id]
            alert["lat"] = existing.get("lat")
            alert["lon"] = existing.get("lon")
        else:
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
                alert["lat"] = random.uniform(-60, 70)
                alert["lon"] = random.uniform(-170, 170)
        final_alerts.append(alert)

    alerts = final_alerts

    # Score and limit
    for alert in alerts:
        alert["score"] = score_event(alert)

    alerts.sort(key=lambda x: x.get("score", 1), reverse=True)
    alerts = alerts[:50]

    # Generate insights & correlations
    insights = generate_insights(alerts)
    correlations = detect_correlations(alerts)

    # Save
    radar_data = {
        "last_update": now,
        "alerts": alerts,
        "insights": insights,
        "correlations": correlations
    }

    os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(radar_data, f, indent=2)

    print(f"✅ Radar data saved — {len(alerts)} total alerts")

    # Terminal output
    print("\n" + "=" * 40)
    print("🧠 INSIGHTS ENGINE OUTPUT")
    print("=" * 40)
    for i in insights:
        print(i)
    print("\n" + "-" * 30 + "\n")


def main():
    print("🚀 Internet Radar Daemon started (daily mode)")

    while True:
        try:
            print(f"\n[{datetime.datetime.utcnow()}] Collecting radar data...\n")

            if ALLOW_SHODAN:
                has_credits = check_shodan_credits()
                if not has_credits:
                    print("⚠️  Skipping Shodan this cycle due to low credits.")

            collect_data()

            print(f"✅ Cycle complete. Next run in 24 hours.\n")
            time.sleep(POLL_INTERVAL_SECONDS)

        except KeyboardInterrupt:
            print("\n👋 Daemon stopped by user.")
            break
        except Exception as e:
            print(f"❌ Unexpected error in main loop: {e}")
            time.sleep(3600)  # Sleep 1 hour on crash


if __name__ == "__main__":
    # Recommend using environment variable for key
    if not os.getenv("SHODAN_API_KEY"):
        print("⚠️  SHODAN_API_KEY environment variable not set. Shodan may fail.")

    main()