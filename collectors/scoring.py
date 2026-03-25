def score_event(event):

    score = event.get("severity", 1)

    title = event["title"].lower()

    if "critical" in title:
        score += 5

    if "ransomware" in title:
        score += 4

    if "zero-day" in title:
        score += 6

    return score
