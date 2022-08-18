import os
from datetime import datetime
from hashlib import new

import requests

from constants import Constants


class Notifier:
    def __init__(self, new_cves: dict):
        if len(new_cves) == 0 or not Constants.ROCKETCHAT_WEBHOOK:
            return

        self.new_cves = new_cves
        self.notify_rocketchat()

    def notify_rocketchat(self):
        msg = f"Found {len(self.new_cves)} new CVE's within last {Constants.INTERVAL.days} days:"
        attachments = []

        for cve in self.new_cves.values():
            date: str = cve["date"]
            keyword: str = cve["keyword"].upper()
            name: str = cve["name"]
            title: str = f"{date} | {keyword} - {name}"

            attachments.append(
                {
                    "title": title,
                    "title_link": cve["url"],
                    "text": cve["description"],
                    "color": "danger",
                }
            )

        data = {"text": msg, "attachments": attachments}

        requests.post(Constants.ROCKETCHAT_WEBHOOK, json=data)
