# correlation_engine.py
def detect_correlations(alerts):
    findings = []
    titles = [a.get("title", "").lower() for a in alerts]

    # Generic exploit detection
    exploit_hits = [t for t in titles if "exploit" in t]
    if exploit_hits:
        findings.append({
            "title": "🚨 EXPLOIT ACTIVITY DETECTED",
            "details": f"{len(exploit_hits)} exploit-related events found",
            "impact": "Systems may be actively targeted",
            "severity": 5
        })

    # SQL Injection
    sql_hits = [t for t in titles if "sql injection" in t or "sql" in t and "injection" in t]
    if sql_hits:
        findings.append({
            "title": "⚠️ SQL INJECTION VULNERABILITIES",
            "details": f"{len(sql_hits)} SQL injection issues detected",
            "impact": "Attackers may access or modify databases",
            "severity": 4
        })

    # XSS
    xss_hits = [t for t in titles if "xss" in t]
    if xss_hits:
        findings.append({
            "title": "⚠️ CROSS-SITE SCRIPTING (XSS)",
            "details": f"{len(xss_hits)} XSS vulnerabilities detected",
            "impact": "Attackers may execute malicious scripts",
            "severity": 3
        })

    # Buffer overflow / memory issues
    overflow_hits = [t for t in titles if "buffer overflow" in t or "memory corruption" in t]
    if overflow_hits:
        findings.append({
            "title": "🚨 MEMORY CORRUPTION RISK",
            "details": f"{len(overflow_hits)} buffer overflow vulnerabilities",
            "impact": "Could lead to remote code execution",
            "severity": 5
        })

    # Shodan/exposed services
    exposed_hits = [t for t in titles if "exposed" in t or "shodan" in t]
    if exposed_hits:
        findings.append({
            "title": "🌐 EXPOSED SERVICES DETECTED",
            "details": f"{len(exposed_hits)} internet-exposed assets found",
            "impact": "Increased attack surface",
            "severity": 4
        })

    return findings