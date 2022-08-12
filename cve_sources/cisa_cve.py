from datetime import datetime
from operator import contains

import requests
from constants import Constants


class CisaCVE:
    def __init__(self, saved_cves, now, start_date, inventory, new_cves):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        root = requests.get(Constants.cisa_cve_url).json()
        
        for child in root["vulnerabilities"]:
            name = child["cveID"]
            seq = name.replace("CVE-", "")
            if seq.startswith(str(self.now.year)) or seq.startswith(str(self.start_date.year)):
                if contains(self.saved_cves.keys(), name) or contains(self.new_cves.keys(), name):
                    continue

                date = child["dateAdded"]
                date_converted = datetime.strptime(date, "%Y-%m-%d")
                description = child["shortDescription"]

                product = child["product"].lower()
                vendor_project = child["vendorProject"].lower()

                if date_converted.timestamp() < self.start_date.timestamp():
                    continue

                keyword = next((key.lower() for key in self.inventory if key in product or key in vendor_project), False)
                if keyword:
                    self.new_cves[name] = {
                        "name": name,
                        "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                        "date": date_converted.strftime("%d.%m.%Y"),
                        "keyword": keyword,
                        "description": description
                    }
        
        return self.new_cves
