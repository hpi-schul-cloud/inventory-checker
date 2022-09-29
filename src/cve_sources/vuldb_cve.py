import xml.etree.ElementTree as ET
from datetime import datetime
from operator import contains

import requests
from constants import Constants
from inventory_checker import InventoryChecker
from utils.severity_util import SeverityUtil


def fetch_cves(invch: InventoryChecker):
    response = requests.get(Constants.VULDB_CVE_URL)
    root = ET.fromstring(response.content)

    for child in root[0].findall("item"):
        date = child.find("pubDate").text
        date_converted = datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z")

        if date_converted.timestamp() < invch.start_date.timestamp():
            continue

        name: str = child.find("title").text.split(" | ")[0]

        description = child.find("description").text
        url = child.find("link").text

        # First matching keyword or False if no keyword matches (generator empty)
        keyword = next(
            (
                key
                for key in invch.inventory
                if key["keyword"].lower() in description.lower()
            ),
            False,
        )

        if keyword:
            if contains(invch.saved_cves.keys(), name):
                if contains(invch.saved_cves[name].keys(), "notAffected"):
                    continue

            severity_data = None

            for category in child.findall("category"):
                if category.text.startswith("Risk: "):
                    severity_data = category.text
                    break

            severity = "unknown"

            if severity_data != None:
                severity = SeverityUtil.getUniformSeverity(severity_data.replace("Risk: ", ""))

            # Replace severity of cve's that have an unknown severity
            if contains(invch.saved_cves.keys(), name) or contains(
            invch.new_cves.keys(), name
            ):
                if invch.new_cves.get(name) != None and invch.new_cves.get(name)["severity"] == "unknown":
                    invch.new_cves.get(name)["severity"] = severity
                continue

            invch.new_cves[name] = {
                "name": name,
                "url": url,
                "date": date_converted.strftime("%d.%m.%Y"),
                "keyword": keyword["keyword"].lower(),
                "description": description,
                "severity": severity,
                "affected_versions": [],
            }
