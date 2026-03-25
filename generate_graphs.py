import json
import plotly.graph_objects as go

HISTORY_FILE = "data/shodan_history.json"

with open(HISTORY_FILE) as f:
    history = json.load(f)

for service, records in history.items():

    times = [r["time"] for r in records]
    counts = [r["count"] for r in records]

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=times,
        y=counts,
        mode="lines+markers",
        name=service
    ))

    fig.update_layout(
        title=f"{service} Internet Exposure",
        xaxis_title="Time",
        yaxis_title="Host Count"
    )

    output_file = f"data/{service}_trend.html"

    fig.write_html(output_file)

    print("Generated:", output_file)
