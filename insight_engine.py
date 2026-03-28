def generate_insights(alerts):
    insights = []

    if not alerts:
        return ["No activity detected"]

    # 🚨 Exploit detection
    exploit_hits = [a for a in alerts if "exploit" in a.get("title", "").lower()]
    if exploit_hits:
        insights.append(f"🚨 Exploit activity detected: {len(exploit_hits)} events")

    # 🔥 Top threat
    top = max(alerts, key=lambda x: x.get("severity", 0))
    insights.append(f"🔥 Top Threat: {top['title']}")

    # 📡 Count by source
    sources = {}
    for a in alerts:
        src = a.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1

    busiest = max(sources, key=sources.get)
    insights.append(f"📡 Most Active Source: {busiest}")

    # 🔥 CVE surge detection (moved OUTSIDE loop)
    cve_count = len([a for a in alerts if a.get("source") == "CVE"])
    if cve_count >= 5:
        insights.append(f"🔥 Surge in vulnerabilities detected ({cve_count} CVEs)")

    # ⚠️ High severity
    high = [a for a in alerts if a.get("severity", 0) >= 4]
    insights.append(f"⚠️ High Severity Alerts: {len(high)}")

    # 🧭 System mood (NOW inside function)
    avg_score = sum(a.get("score", 0) for a in alerts) / len(alerts)

    if avg_score >= 6:
        mood = "🔥 HIGH RISK"
    elif avg_score >= 4:
        mood = "⚠️ ELEVATED"
    else:
        mood = "🟢 CALM"

    insights.append(f"🧭 Internet Risk Level: {mood}")

    return insights


