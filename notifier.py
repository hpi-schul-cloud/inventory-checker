import os
from datetime import datetime

import requests

from constants import Constants


class Notifier:
    def __init__(self, new_cves):
        if len(new_cves) == 0:
            return

        self.notify_rocketchat(new_cves)

    def notify_rocketchat(self, new_cves):
        msg = f"Found {len(new_cves)} new CVE's within last {Constants.interval.days} days:"
        attachments = []

        for cve in new_cves.values():
            date = cve["date"]
            key = cve["keyword"].upper()
            name = cve["name"]
            title = f"{date} | {key} - {name}"

            attachments.append({
                "title": title,
                "title_link": cve["url"],
                "text": cve["description"],
                "color": "danger"
            })

        data = {
            "text": msg,
            "attachments": attachments
        }

        requests.post(os.getenv("ROCKETCHAT_WEBHOOK"), json=data)
