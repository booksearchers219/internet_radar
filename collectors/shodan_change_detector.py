import requests
import json
import os
import datetime

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    raise RuntimeError("SHODAN_API_KEY environment variable not set")

TRACK_FILE = "data/shodan_history.json"

QUERIES = {
    "MongoDB": "port:27017",
    "ICS": "port:502",
    "RDP": "port:3389"
}


def get_count(query):

    url = f"https://api.shodan.io/shodan/host/count?key={SHODAN_API_KEY}&query={query}"

    try:

        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            print("Shodan HTTP error:", r.status_code)
            return 0

        data = r.json()

        return data.get("total", 0)

    except Exception as e:

        print("Shodan request failed:", e)

        return 0


def detect_changes():

    results = {}
    timestamp = datetime.datetime.utcnow().isoformat()

    for name, query in QUERIES.items():

        count = get_count(query)

        print(name, "hosts:", count)

        results[name] = count

    # load history
    if os.path.exists(TRACK_FILE):
        with open(TRACK_FILE) as f:
            history = json.load(f)
    else:
        history = {}

    alerts = []

    for name, new in results.items():

        if name not in history:
            history[name] = []

        # get previous count if exists
        old = history[name][-1]["count"] if history[name] else 0

        change = new - old

        if abs(change) > 0:

            lat = None
            lon = None

            try:
                host_url = f"https://api.shodan.io/shodan/host/search?key={SHODAN_API_KEY}&query={QUERIES[name]}"
                r = requests.get(host_url, timeout=10)
                data = r.json()

                if data.get("matches"):
                    host = data["matches"][0]

                    lat = host.get("location", {}).get("latitude")
                    lon = host.get("location", {}).get("longitude")

            except Exception as e:
                print("Location lookup failed:", e)

            alerts.append({
                "title": f"{name} exposure changed by {change}",
                "url": f"https://www.shodan.io/search?query={QUERIES[name]}",
                "source": "Shodan Change",
                "severity": 6,
                "lat": lat,
                "lon": lon
            })

        # append new record
        history[name].append({
            "time": timestamp,
            "count": new
        })

    # save history
    with open(TRACK_FILE, "w") as f:
        json.dump(history, f, indent=2)

    return alerts