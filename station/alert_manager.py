import json
import os
from datetime import datetime, timezone

from .packet_parser import packet_to_json_ready


# build the final alert data used for saving and sending
def build_alert_data(alert):
    alert_data = {
        "time": datetime.now(timezone.utc).isoformat(),
        "level": alert["level"],
        "type": alert["type"],
        "message": alert["message"],
        "packet": packet_to_json_ready(alert["packet"]),
    }
    return alert_data


# save alerts in a jsonl file
def save_alerts(alerts, alert_file):
    if not alerts:
        return

    folder = os.path.dirname(alert_file)
    if folder:
        os.makedirs(folder, exist_ok=True)

    with open(alert_file, "a", encoding="utf-8") as file:
        for alert in alerts:
            alert_data = build_alert_data(alert)
            file.write(json.dumps(alert_data) + "\n")


# print alerts locally on the nids side
def print_alerts(alerts):
    for alert in alerts:
        print("[ALERT]", alert["type"], "-", alert["message"])
