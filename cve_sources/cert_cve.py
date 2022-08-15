from datetime import datetime
from operator import contains

import requests
from constants import Constants


class CertCVE:
    def __init__(self, saved_cves: dict, now: datetime, start_date: datetime, inventory: list, new_cves: dict):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        root: dict = requests.get(Constants.cert_cve_url).json()

        for child in root["content"]:
            if len(child["cves"]) == 0: continue

            date: str = child["published"]
            date_converted: datetime = datetime.fromisoformat(date)

            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            exit: bool = False
            for cve in child["cves"]:
                    if contains(self.saved_cves.keys(), cve) or contains(
                        self.new_cves.keys(), cve
                    ):
                        exit = True
                        break

            if exit: continue

            name: str = child["cves"][len(child["cves"]) - 1]
            description = child["title"]

            keyword: bool = next(
                (
                    key.lower()
                    for key in self.inventory
                    if key in description.lower()
                ),
                False,
            )
            if keyword:
                self.new_cves[name] = {
                    "name": name,
                    "url": f"https://wid.cert-bund.de/portal/wid/securityadvisory?name={child['name']}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                }

        return self.new_cves
