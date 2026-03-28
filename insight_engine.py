def generate_insights(alerts):
    insights = []

    if not alerts:
        return ["No activity detected"]

    # 🚨 Exploit detection
    exploit_hits = [a for a in alerts if "exploit" in a.get("title", "").lower()]
    if exploit_hits:
        insights.append(f"🚨 Exploit activity detected: {len(exploit_hits)} events")

    top_threats = []

    titles = [a.get("title", "").lower() for a in alerts]

    # 🔥 Classic vuln types
    if any("sql injection" in t for t in titles):
        top_threats.append("SQL Injection")

    if any("xss" in t for t in titles):
        top_threats.append("XSS")

    if any("buffer overflow" in t for t in titles):
        top_threats.append("Memory Corruption")

    # 🌍 NEW — Shodan / exposure detection
    if any("exposed to the internet" in t for t in titles):
        top_threats.append("Exposed Services")

    if any(a.get("source") == "Shodan" for a in alerts):
        top_threats.append("Internet Exposure")

    # 🔐 NEW — auth / access issues
    if any("auth" in t for t in titles):
        top_threats.append("Authentication Issues")

    # 💣 NEW — injection (broader match)
    if any("injection" in t for t in titles):
        top_threats.append("Injection Vulnerabilities")

        top_threats = list(set(top_threats))

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





    pulse = {
        "risk_level": mood,
        "top_threats": top_threats,
        "total_alerts": len(alerts),
        "high_severity": len(high)
    }

    # Remove any existing pulse objects first
    insights = [i for i in insights if not isinstance(i, dict)]

    # Add fresh pulse
    insights.append(pulse)

    return insights


