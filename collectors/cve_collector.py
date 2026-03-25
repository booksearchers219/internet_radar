import requests

def get_cves():

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"

    try:
        r = requests.get(url, timeout=10)
        data = r.json()

        alerts = []

        for item in data["vulnerabilities"]:

            cve = item["cve"]["id"]

            desc = item["cve"]["descriptions"][0]["value"]

            alerts.append({
                "title": f"{cve}: {desc[:120]}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "source": "CVE",
                "severity": 5
            })

        return alerts

    except Exception as e:
        print("CVE collector error:", e)
        return []