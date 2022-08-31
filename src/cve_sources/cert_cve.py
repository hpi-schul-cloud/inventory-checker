from datetime import datetime
from operator import contains

import requests
from constants import Constants
from utils.severity_util import SeverityUtil


class CertCVE:
    def fetch_cves(self):
        root: dict = requests.get(Constants.CERT_CVE_URL).json()

        for child in root["content"]:
            if len(child["cves"]) == 0: continue

            date: str = child["published"]
            date_converted: datetime = datetime.fromisoformat(date)

            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child["cves"][len(child["cves"]) - 1]
            description = child["title"]

            keyword: bool = next(
                (
                    key
                    for key in self.inventory
                    if key["keyword"].lower() in description.lower()
                ),
                False,
            )
            if keyword:
                severity = "unknown"

                if child["classification"] != None:
                    severity = SeverityUtil.getUniformSeverity(child["classification"])

                exit: bool = False
                for cve in child["cves"]:
                    # Replace severity of cve's that have an unknown severity
                    if contains(self.saved_cves.keys(), cve) or contains(
                        self.new_cves.keys(), cve
                    ):
                        if self.new_cves.get(name) != None and self.new_cves.get(name)["severity"] == "unknown":
                            self.new_cves.get(name)["severity"] = severity
                        exit = True
                        break

                if exit: continue

                self.new_cves[name] = {
                    "name": name,
                    "url": f"https://wid.cert-bund.de/portal/wid/securityadvisory?name={child['name']}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword["keyword"].lower(),
                    "description": description,
                    "severity": severity,
                    "affected_versions": [],
                }
