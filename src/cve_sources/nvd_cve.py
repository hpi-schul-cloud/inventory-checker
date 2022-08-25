from datetime import datetime
from operator import contains

import requests
from constants import Constants
from utils.severity_util import SeverityUtil


class NvdCVE:
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
                impact_data: list = child["impact"]
                severity = "unknown"

                versions = NvdCVE.retrieve_versions(child["configurations"]["nodes"])

                if contains(impact_data.keys(), "baseMetricV3"):
                    severity = SeverityUtil.getUniformSeverity(impact_data["baseMetricV3"]["cvssV3"]["baseSeverity"])

                # Replace severity and affected products of cve's that have an unknown severity or empty []
                if contains(self.saved_cves.keys(), name) or contains(
                self.new_cves.keys(), name
                ):
                    if self.new_cves.get(name) != None and self.new_cves.get(name)["severity"] == "unknown":
                        self.new_cves.get(name)["severity"] = severity

                    if self.new_cves.get(name) != None and len(self.new_cves.get(name)["affected_versions"]) == 0:
                        self.new_cves.get(name)["affected_versions"] = versions
                    continue

                self.new_cves[name] = {
                    "name": name,
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword,
                    "description": description,
                    "severity": severity,
                    "affected_versions": versions,
                }

    def retrieve_versions(child):
        versions = []

        for node_data in child:
            if node_data["operator"] == "AND":
                NvdCVE.retrieve_versions(node_data["children"])

            if node_data["operator"] == "OR":
                for version_data in node_data["cpe_match"]:
                    start = ""
                    end = ""
                    
                    if version_data.get("versionStartIncluding"):
                        start = version_data["versionStartIncluding"]
                    
                    if version_data.get("versionEndExcluding"):
                        end = version_data["versionEndExcluding"]

                    if start == "" and end == "":
                        continue

                    version = start + "-" + end

                    if not contains(versions, version):
                        versions.append(version)

        return versions
