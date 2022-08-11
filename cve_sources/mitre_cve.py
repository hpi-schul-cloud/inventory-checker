
from operator import contains
import json
from datetime import datetime
from xml.dom.minidom import Element

import re
import requests
import xml.etree.ElementTree as ET
from constants import Constants

class MitreCVE:
    def __init__(self, savedCves, now, start_date, inventory, newCves):
        self.savedCves = savedCves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.newCves = newCves
        self.fetch_and_save_cves()

    def fetch_and_save_cves(self):
        response = requests.get(Constants.mitre_cve_url)
        root = ET.fromstring(response.content)
        namespace = self.namespace(root)

        for child in root:
            name = child.attrib["name"]
            seq = child.attrib["seq"]
            if seq.startswith(str(self.now.year)) or seq.startswith(str(self.start_date.year)):
                if contains(self.savedCves.keys(), name):
                    continue

                phase = child.find(".//{" + namespace + "}phase")
                date = phase.attrib["date"]
                phaseText = phase.text.lower()
                description = child.find(".//{" + namespace + "}desc").text.lower()
                if description.startswith("**") or datetime.strptime(date, "%Y%m%d").microsecond < self.start_date.microsecond:
                    continue

                keyword = next((key.lower() for key in self.inventory if key in description), False)
                if keyword:
                    self.newCves[name] = {
                        "name": name,
                        "url": "https://www.cve.org/CVERecord?id={name}",
                        "date": date,
                        "keyword": keyword,
                        "phase": phaseText,
                        "description": description
                    }

        self.save_cves(self.newCves)

    def namespace(self, element: Element):
        m = re.match(r'\{(.*)\}', element.tag)
        return m.group(1) if m else ''

    def save_cves(self, cves):
        file = open(Constants.cve_file_path, "w")
        self.savedCves.update(cves)
        file.write(json.dumps(self.savedCves))
        file.close()