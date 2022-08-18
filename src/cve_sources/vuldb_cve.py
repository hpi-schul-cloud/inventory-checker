import re
import xml.etree.ElementTree as ET
from datetime import datetime
from operator import contains
from xml.dom.minidom import Element

import requests
from constants import Constants


class VuldbCVE:
    def __init__(self, saved_cves: dict, now: datetime, start_date: datetime, inventory: list, new_cves: dict):
        self.saved_cves = saved_cves
        self.now = now
        self.start_date = start_date
        self.inventory = inventory
        self.new_cves = new_cves

    def fetch_cves(self):
        response = requests.get(Constants.VULDB_CVE_URL)
        root = ET.fromstring(response.content)

        for child in root[0].findall("item"):
            date = child.find("pubDate").text
            date_converted = datetime.strptime(date, "%a, %d %b %Y %H:%M:%S %z")
            
            if date_converted.timestamp() < self.start_date.timestamp():
                continue

            name: str = child.find("title").text.split(" | ")[0]

            if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
            ):
                continue
            
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
                self.new_cves[name] = {
                    "name": name,
                    "url": url,
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                }

        return self.new_cves
