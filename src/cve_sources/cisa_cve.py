from datetime import datetime
from operator import contains

import requests
from prometheus_client import Gauge

from constants import Constants
from cve_sources.abstract_cve_source import CVESource


class CisaCVEs (CVESource):
    STATUS_REPORT = Gauge('invch_cisa', 'CISA CVE source available in Inventory Checker')
    NAME = "CISA"

    @staticmethod
    def fetch_cves(invch):
        root: dict = requests.get(Constants.CISA_CVE_URL).json()

        for child in root["vulnerabilities"]:
            date: str = child["dateAdded"]
            date_converted: datetime = datetime.strptime(date, "%Y-%m-%d")

            if date_converted.timestamp() < invch.start_date.timestamp():
                continue

            name: str = child["cveID"]

            if contains(invch.saved_cves.keys(), name) or contains(
                invch.new_cves.keys(), name
            ):
                continue

            description: str = child["shortDescription"]

            product: str = child["product"].lower()
            vendor_project: str = child["vendorProject"].lower()

            # First matching keyword or False if no keyword matches (generator empty)
            keyword = next(
                (
                    key
                    for key in invch.inventory
                    if key["keyword"].lower() in product or key["keyword"].lower() in vendor_project
                ),
                False,
            )
            if keyword:
                invch.new_cves[name] = {
                    "name": name,
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword["keyword"].lower(),
                    "description": description,
                    "severity": "unknown",
                    "affected_versions": [],
                }
