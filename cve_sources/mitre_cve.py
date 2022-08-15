import re
import xml.etree.ElementTree as ET
from datetime import datetime
from operator import contains
from xml.dom.minidom import Element

import requests
from constants import Constants


class MitreCVE:
    def __init__(self, saved_cves: dict, now: datetime, start_date: datetime, inventory: list, new_cves: dict):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        response = requests.get(Constants.mitre_cve_url)
        root = ET.fromstring(response.content)
        namespace = self.namespace(root)

        for child in root:
            phase = child.find(".//{" + namespace + "}phase")
            if phase is None:
                continue

            date = phase.attrib["date"]
            date_converted = datetime.strptime(date, "%Y%m%d")
            
            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child.attrib["name"]

            if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
            ):
                continue

            description = child.find(".//{" + namespace + "}desc").text

            # if it starts with ** its reserved or shouldn't be used
            if description.startswith("**"):
                continue

            keyword = next(
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
                    "url": f"https://www.cve.org/CVERecord?id={name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                }

        return self.new_cves

    def namespace(self, element: Element):
        m = re.match(r"\{(.*)\}", element.tag)
        return m.group(1) if m else ""
