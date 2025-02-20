from datetime import datetime
from operator import contains

import requests
import semver
from prometheus_client import Gauge

from constants import Constants
from cve_sources.abstract_cve_source import CVESource
from utils.severity_util import SeverityUtil
import re


class NvdCVEs(CVESource):
    STATUS_REPORT = Gauge('invch_nvd', 'NVD CVE source available in Inventory Checker')
    NAME = "NVD"

    @staticmethod
    def fetch_cves(invch):
        startDate: str = (
                "?pubStartDate="
                + invch.start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")
        )
        endDate: str = (
                "&pubEndDate="
                + invch.now.strftime("%Y-%m-%dT%H:%M:%S.%f")
        )
        
        all_cves_parsed_flag: bool = False
        start_index = 0
        root: list = []

        while not all_cves_parsed_flag:
            result: list = requests.get(
                Constants.NVD_CVE_URL + startDate + endDate + "&resultsPerPage=2000" + "&startIndex=" + str(start_index)
                ).json()
            if start_index == 0:
                root = result["vulnerabilities"]
            else:
                root.extend(result["vulnerabilities"])
            total_results: int = result["totalResults"]
            results_loaded: int = result["resultsPerPage"] + result["startIndex"]
            if total_results <= (results_loaded) or result["resultsPerPage"] == 0:
                all_cves_parsed_flag = True
            else:
                start_index = start_index + 1999

        
        for child in root:
            date = child["cve"]["lastModified"]
            date_converted: datetime = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f")

            if date_converted.timestamp() < invch.start_date.timestamp():
                continue
            name: str = child["cve"]["id"]

            description_data: list = child["cve"]["descriptions"]

            description = next(
                (elem for elem in description_data if elem["lang"] == "en"),
                description_data[0],
            )["value"]


            # First matching keyword or False if no keyword matches (generator empty)
            keyword = next(
                (key for key in invch.inventory if re.search(rf'\b{re.escape(key["keyword"].lower())}\b', description, re.IGNORECASE)),
                False
            )
 
            matched_docker_compose = next(
                (img for img in invch.images if (
                    img["container_name"].lower() in description or
                    img["image"].lower() in description
                )),
                False
            )

            if keyword:
                matched_entry = {"keyword": keyword, "version": "unknown"}  
                matched_type = "image"
            elif matched_docker_compose:
                matched_entry = matched_docker_compose
                matched_type = "docker-compose"
            else:
               continue 
            if keyword:
                if contains(invch.saved_cves.keys(), name):
                    if contains(invch.saved_cves[name].keys(), "notAffected"):
                        continue

                affected = False
                impact_data = child["cve"]["metrics"]
                severity = "unknown"

                for key in invch.inventory:
                    if affected:
                        break

                    keyword = key
                    if keyword["keyword"].lower() in description.lower():
                        current_version: str = key["version"]

                        if "configurations" in child["cve"]:
                            versions = NvdCVEs.retrieve_versions(child["cve"]["configurations"][0]["nodes"], keyword["keyword"])
                            
                        else: 
                            versions = []

                        if len(versions) == 0:
                            affected = True

                        try:
                            for version in versions:
                                version_start = version.split(" - ")[0]
                                version_end = version.split(" - ")[1]

                                if version_start == "" and version_end == "":
                                    continue

                                if version_start == "":
                                    if semver.compare(current_version, version_end) <= 0:
                                        affected = True
                                        break
                                elif version_end == "":
                                    if semver.compare(current_version, version_start) >= 0:
                                        affected = True
                                        break
                                elif semver.compare(current_version, version_start) >= 0 and semver.compare(
                                        current_version,
                                        version_end) <= 0:
                                    affected = True
                                    break
                        except ValueError:
                            affected = True  # Manual check if version is affected is required
                            break

                if not affected:
                    if contains(invch.new_cves.keys(), name):
                        del invch.new_cves[name]
                    if contains(invch.saved_cves.keys(), name):
                        invch.saved_cves[name]["notAffected"] = True
                    continue

                if contains(impact_data.keys(), "baseMetricV30"):
                    severity = SeverityUtil.getUniformSeverity(impact_data["baseMetricV30"]["cvssData"]["baseSeverity"])

                # Replace severity and affected products of cve's that have an unknown severity or empty []
                if contains(invch.saved_cves.keys(), name) or contains(
                        invch.new_cves.keys(), name
                ):
                    if invch.new_cves.get(name) != None and invch.new_cves.get(name)["severity"] == "unknown":
                        invch.new_cves.get(name)["severity"] = severity

                    if invch.new_cves.get(name) != None and len(invch.new_cves.get(name)["affected_versions"]) == 0:
                        invch.new_cves.get(name)["affected_versions"] = versions
                    continue

                keyword_value = matched_entry.get("keyword", matched_entry.get("container_name", "unknown"))

                if isinstance(matched_entry["keyword"], dict):
                    affected_version = matched_entry["keyword"].get("version", "unknown")
                else:
                    affected_version = matched_entry.get("version", "unknown")

                invch.new_cves[name] = {
                    "name": name,
                    "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                    "date": date_converted.strftime("%d.%m.%Y"),
                    "keyword": keyword_value,
                    "description": description,
                    "severity": severity,
                    "affected_versions": [affected_version],
                    "type": matched_type,
                    "from": "NVD"
                }


    @staticmethod
    def retrieve_versions(child, keyword):
        versions = []
        
        for node_data in child:
            for version_data in node_data["cpeMatch"]:
                start = ""
                end = ""

                if not contains(version_data.get("criteria").lower(), keyword.lower()):
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