from datetime import datetime
from operator import contains

import requests
from constants import Constants


class NvdCVE:
    def __init__(self, saved_cves, now, start_date, inventory, new_cves):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        startDate = "?pubStartDate=" + self.start_date.isoformat()[:-9].replace(".", ":") + "%20UTC%2B00:00"
        endDate = "&pubEndDate=" + self.now.isoformat()[:-9].replace(".", ":") + "%20UTC%2B00:00"
        root = requests.get(Constants.nvd_cve_url + startDate + endDate + "&resultsPerPage=2000").json()
        
        for child in root["result"]["CVE_Items"]:
            name = child["cve"]["CVE_data_meta"]["ID"]
            seq = name.replace("CVE-", "")
            if seq.startswith(str(self.now.year)) or seq.startswith(str(self.start_date.year)):
                if contains(self.saved_cves.keys(), name) or contains(self.new_cves.keys(), name):
                    continue

                date = child["lastModifiedDate"]
                date_converted = datetime.strptime(date, "%Y-%m-%dT%H:%Mz")

                description_data = child["cve"]["description"]["description_data"]
                description = next((elem for elem in description_data if elem["lang"] == "en"), description_data[0])["value"]

                if date_converted.timestamp() < self.start_date.timestamp():
                    continue

                keyword = next((key.lower() for key in self.inventory if key in description.lower()), False)
                if keyword:
                    self.new_cves[name] = {
                        "name": name,
                        "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                        "date": date_converted.strftime("%d.%m.%Y"),
                        "keyword": keyword,
                        "description": description
                    }
        
        return self.new_cves
