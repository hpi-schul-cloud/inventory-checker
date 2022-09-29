from datetime import datetime
from operator import contains

import requests
from constants import Constants
from utils.severity_util import SeverityUtil


def fetch_cves(invch):
    root: dict = requests.get(Constants.CERT_CVE_URL).json()

    for child in root["content"]:
        if len(child["cves"]) == 0: continue

        date: str = child["published"]
        date_converted: datetime = datetime.fromisoformat(date)

        if date_converted.timestamp() < invch.start_date.timestamp():
            continue

        name: str = child["cves"][len(child["cves"]) - 1]
        description = child["title"]

        # First matching keyword or False if no keyword matches (generator empty)
        keyword = next(
            (
                key
                for key in invch.inventory
                if key["keyword"].lower() in description.lower()
            ),
            False
        )
        if keyword:
            if contains(invch.saved_cves.keys(), name):
                if contains(invch.saved_cves[name].keys(), "notAffected"):
                    continue

            severity = "unknown"

            if child["classification"] != None:
                severity = SeverityUtil.getUniformSeverity(child["classification"])

            exit: bool = False
            for cve in child["cves"]:
                # Replace severity of cve's that have an unknown severity
                if contains(invch.saved_cves.keys(), cve) or contains(
                        invch.new_cves.keys(), cve
                ):
                    if invch.new_cves.get(name) != None and invch.new_cves.get(name)["severity"] == "unknown":
                        invch.new_cves.get(name)["severity"] = severity
                    exit = True
                    break

            if exit: continue

            invch.new_cves[name] = {
                "name": name,
                "url": f"https://wid.cert-bund.de/portal/wid/securityadvisory?name={child['name']}",
                "date": date_converted.strftime("%d.%m.%Y"),
                "keyword": keyword["keyword"].lower(),
                "description": description,
                "severity": severity,
                "affected_versions": [],
            }
