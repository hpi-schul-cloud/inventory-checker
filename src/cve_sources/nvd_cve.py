from datetime import datetime
from operator import contains

import requests
import semver
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
                    key
                    for key in self.inventory
                    if key["keyword"].lower() in description.lower()
                ),
                False,
            )
            if keyword:
                affected = False
                impact_data: list = child["impact"]
                severity = "unknown"

                for key in self.inventory:
                    keyword = key["keyword"]
                    if keyword.lower() in description.lower():
                        current_version: str = key["version"]

                        versions = NvdCVE.retrieve_versions(child["configurations"]["nodes"], keyword)

                        for version in versions:
                            version_start = version.split(" - ")[0]
                            version_end = version.split(" - ")[1]
                            
                            if version_start == "":
                                if semver.compare(current_version, version_end) <= 0:
                                    affected = True
                                    break

                            if version_end == "":
                                if semver.compare(current_version, version_start) >= 0:
                                    affected = True
                                    break

                            if semver.compare(current_version, version_start) >= 0 and semver.compare(current_version, version_end) <= 0:
                                    affected = True
                                    break
                        
                if not affected:
                    if contains(self.new_cves.keys(), name):
                        del self.new_cves[name]
                    continue

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

    def retrieve_versions(child, keyword):
        versions = []

        for node_data in child:
            if node_data["operator"] == "AND":
                NvdCVE.retrieve_versions(node_data["children"], keyword)

            if node_data["operator"] == "OR":
                for version_data in node_data["cpe_match"]:
                    start = ""
                    end = ""

                    if not contains(version_data.get("cpe23Uri").lower(), keyword.lower()):
                        continue
                    
                    if version_data.get("versionStartIncluding"):
                        start = version_data["versionStartIncluding"]
                    
                    if version_data.get("versionEndExcluding"):
                        end = version_data["versionEndExcluding"]

                    if start == "" and end == "":
                        continue

                    version = start + " - " + end

                    if not contains(versions, version):
                        versions.append(version)

        return versions
