import json
import datetime

def generate_report():

    with open("data/radar.json") as f:
        data = json.load(f)

    today = datetime.date.today()

    report_file = f"data/report_{today}.txt"

    with open(report_file, "w") as f:

        f.write("INTERNET RADAR REPORT\n")
        f.write("=====================\n\n")

        for alert in data["alerts"][:10]:

            f.write(f"{alert['score']} - {alert['title']}\n")
            f.write(f"{alert['url']}\n\n")

    print("Daily report generated:", report_file)
