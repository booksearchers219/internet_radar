from flask import Flask, render_template, send_from_directory
import json

app = Flask(__name__)

DATA_FILE = "data/radar.json"


def load_data():
    try:
        with open(DATA_FILE) as f:
            return json.load(f)
    except:
        return {"alerts": [], "last_update": "none"}


@app.route("/")
def home():
    data = load_data()
    return render_template("dashboard.html", data=data, insights=data.get("insights", []))


# NEW ROUTE — serves chart files
@app.route("/data/<path:filename>")
def data_files(filename):
    return send_from_directory("data", filename)


@app.route("/map")
def cyber_map():
    return render_template("map.html")


import random


@app.route("/alerts")
def alerts_api():
    data = load_data()

    import random

    regions = [
        (38.90, -77.03),
        (37.77, -122.41),
        (40.71, -74.00),
        (51.50, -0.12),
        (48.85, 2.35),
        (35.68, 139.69),
        (31.23, 121.47),
    ]

    for alert in data["alerts"]:
        alert["lat"], alert["lon"] = random.choice(regions)

    return data


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
