import requests
from inventory_checker import InventoryChecker

from constants import Constants


class Notifier:
    def post_cve(new_cves):
        if not Constants.ROCKETCHAT_WEBHOOK:
            InventoryChecker.post_to_logger("No Rocketchat message will be sent. ROCKETCHAT_WEBHOOK is not loaded.")
            return
        elif(len(new_cves) == 0):
            InventoryChecker.post_to_logger("No Rocketchat message will be sent. No new CVE's are found.")
            return

        msg = f"Found {len(new_cves)} new CVE's within last {Constants.INTERVAL.days} days:"
        attachments = []

        for cve in new_cves.values():
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
        Notifier.post_message(data)

    def post_message(data):
        if not Constants.ROCKETCHAT_WEBHOOK:
            InventoryChecker.post_to_logger("No Rocketchat message will be sent. ROCKETCHAT_WEBHOOK is not loaded.")
            return

        requests.post(Constants.ROCKETCHAT_WEBHOOK, json=data)
        InventoryChecker.post_to_logger("Sending to Rocketchat: " + data)
