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
    return render_template("dashboard.html", data=data)


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

    for alert in data["alerts"]:

        source = alert.get("source", "")

        if source == "CVE":
            alert["lat"], alert["lon"] = 38.90, -77.03  # Washington DC

        elif source == "GitHub":
            alert["lat"], alert["lon"] = 37.77, -122.41  # San Francisco

        elif source == "Tech News":
            alert["lat"], alert["lon"] = 40.71, -74.00  # New York

        else:
            alert["lat"], alert["lon"] = 20, 0

    return data


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)