import requests
from event_schema import RadarEvent
from datetime import datetime, timedelta


def get_cves():
    alerts = []

    try:
        now = datetime.utcnow()
        yesterday = now - timedelta(days=1)

        start = yesterday.strftime("%Y-%m-%dT%H:%M:%S.000")
        end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}&resultsPerPage=5"

        r = requests.get(url, timeout=10)
        data = r.json()

        for item in data["vulnerabilities"]:
            cve = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]

            event = RadarEvent(
                id=cve,  # ✅ stable ID (fixes your jumping bug)
                title=f"{cve}: {desc[:120]}",
                source="CVE",
                type="vulnerability",
                severity=5,
                url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                timestamp=datetime.utcnow().isoformat()
            )

            alerts.append(event.to_dict())

    except Exception as e:
        print("CVE collector error:", e)

    return alerts