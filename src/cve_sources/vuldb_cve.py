import re
import xml.etree.ElementTree as ET
from datetime import datetime
from operator import contains
from xml.dom.minidom import Element

import requests
from constants import Constants
from utils.severity_util import SeverityUtil


class VuldbCVE:
    def fetch_cves(self):
        response = requests.get(Constants.VULDB_CVE_URL)
        root = ET.fromstring(response.content)

        for child in root[0].findall("item"):
            date = child.find("pubDate").text
            date_converted = datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z")
            
            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child.find("title").text.split(" | ")[0]

            description = child.find("description").text
            url = child.find("link").text

            keyword = next(
                (
                    key.lower()
                    for key in self.inventory
                    if key in description.lower()
                ),
                False,
            )
            
            if keyword:
                severity_data = None

                for category in child.findall("category"):
                    if category.text.startswith("Risk: "):
                        severity_data = category.text
                        break

                severity = "unknown"

                if severity_data != None:
                    severity = SeverityUtil.getUniformSeverity(severity_data.replace("Risk: ", ""))

                # Replace severity of cve's that have an unknown severity
                if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
                ):
                    if self.new_cves.get(name) != None and self.new_cves.get(name)["severity"] == "unknown":
                        self.new_cves.get(name)["severity"] = severity
                    continue

                self.new_cves[name] = {
                    "name": name,
                    "url": url,
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                    "severity": severity,
                    "affected_versions": [],
                }
