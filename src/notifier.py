import os
from datetime import datetime
from hashlib import new
from operator import concat

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

            color = "warning"

            if cve["severity"] == "critical" or cve["severity"] == "high":
                color = "danger"

            attachments.append(
                {
                    "title": title,
                    "title_link": cve["url"],
                    "text": cve["description"],
                    "color": color,
                    "collapsed": True,
                    "fields": [{
                        "title": "Affected versions:",
                        "value": "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])
                    }]
                }
            )

        data = {"text": msg, "attachments": attachments}

        requests.post(Constants.ROCKETCHAT_WEBHOOK, json=data)
