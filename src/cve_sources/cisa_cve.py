from datetime import datetime
from operator import contains

import requests
from constants import Constants


class CisaCVE:
    def fetch_cves(self):
        root: dict = requests.get(Constants.CISA_CVE_URL).json()

        for child in root["vulnerabilities"]:
            date: str = child["dateAdded"]
            date_converted:datetime = datetime.strptime(date, "%Y-%m-%d")

            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child["cveID"]
            
            if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
            ):
                continue

            description: str = child["shortDescription"]

            product: str = child["product"].lower()
            vendor_project: str = child["vendorProject"].lower()

            keyword: bool = next(
                (
                    key
                    for key in self.inventory
                    if key["keyword"].lower() in product or key["keyword"].lower() in vendor_project
                ),
                False,
            )
            if keyword:
                self.new_cves[name] = {
                    "name": name,
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                    "severity": "unknown",
                    "affected_versions": [],
                }
