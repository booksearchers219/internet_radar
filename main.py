from collectors.shodan_collector import get_shodan_alerts
from collectors.secret_collector import get_secret_alerts
from insight_engine import generate_insights

def run_radar():
    print("\n==============================")
    print("🌐 INTERNET RADAR STARTING")
    print("==============================\n")

    alerts = []

    # Collect data
    alerts.extend(get_secret_alerts())
    alerts.extend(get_shodan_alerts())

    # Display results
    if not alerts:
        print("No alerts found.")
        return

    print("🚨 ALERTS:\n")

    for alert in alerts:
        print(f"🔹 {alert['title']}")
        if alert.get("url"):
            print(f"   🔗 {alert['url']}")
        print(f"   📡 Source: {alert['source']}")
        print(f"   ⚠️ Severity: {alert['severity']}")
        print()

        print("\n🧠 INSIGHTS:\n")

        insights = generate_insights(alerts)

        for i in insights:
            print(i)


if __name__ == '__main__':
    run_radar()