from datetime import datetime
from operator import contains

import requests
from constants import Constants


class NvdCVE:
    def __init__(self, saved_cves: dict, now: datetime, start_date: datetime, inventory: list, new_cves: dict):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        startDate: str = (
            "?pubStartDate="
            + self.start_date.isoformat()[:-9].replace(".", ":")
            + "%20UTC%2B00:00"
        )
        endDate: str = (
            "&pubEndDate="
            + self.now.isoformat()[:-9].replace(".", ":")
            + "%20UTC%2B00:00"
        )
        root: dict = requests.get(
            Constants.NVD_CVE_URL + startDate + endDate + "&resultsPerPage=2000"
        ).json()

        for child in root["result"]["CVE_Items"]:
            date: str = child["lastModifiedDate"]
            date_converted: datetime = datetime.strptime(date, "%Y-%m-%dT%H:%Mz")

            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child["cve"]["CVE_data_meta"]["ID"]
            
            if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
            ):
                continue

            description_data: list = child["cve"]["description"]["description_data"]
            description = next(
                (elem for elem in description_data if elem["lang"] == "en"),
                description_data[0],
            )["value"]

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
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                }

        return self.new_cves
