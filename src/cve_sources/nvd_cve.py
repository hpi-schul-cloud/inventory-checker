from datetime import datetime
from operator import contains

import requests
import semver
from constants import Constants
from inventory_checker import InventoryChecker
from utils.severity_util import SeverityUtil


def fetch_cves(invch: InventoryChecker):
    startDate: str = (
            "?pubStartDate="
            + invch.start_date.isoformat()[:-9].replace(".", ":")
            + "%20UTC%2B00:00"
    )
    endDate: str = (
            "&pubEndDate="
            + invch.now.isoformat()[:-9].replace(".", ":")
            + "%20UTC%2B00:00"
    )
    root: dict = requests.get(
        Constants.NVD_CVE_URL + startDate + endDate + "&resultsPerPage=2000"
    ).json()

    for child in root["result"]["CVE_Items"]:
        date: str = child["lastModifiedDate"]
        date_converted: datetime = datetime.strptime(date, "%Y-%m-%dT%H:%Mz")

        if date_converted.timestamp() < invch.start_date.timestamp():
            continue

        name: str = child["cve"]["CVE_data_meta"]["ID"]

        description_data: list = child["cve"]["description"]["description_data"]
        description = next(
            (elem for elem in description_data if elem["lang"] == "en"),
            description_data[0],
        )["value"]

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

            affected = False
            impact_data = child["impact"]
            severity = "unknown"

            for key in invch.inventory:
                if affected:
                    break

                keyword = key
                if keyword["keyword"].lower() in description.lower():
                    current_version: str = key["version"]

                    versions = retrieve_versions(child["configurations"]["nodes"], keyword["keyword"])

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
                            elif semver.compare(current_version, version_start) >= 0 and semver.compare(current_version,
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

            if contains(impact_data.keys(), "baseMetricV3"):
                severity = SeverityUtil.getUniformSeverity(impact_data["baseMetricV3"]["cvssV3"]["baseSeverity"])

            # Replace severity and affected products of cve's that have an unknown severity or empty []
            if contains(invch.saved_cves.keys(), name) or contains(
                    invch.new_cves.keys(), name
            ):
                if invch.new_cves.get(name) != None and invch.new_cves.get(name)["severity"] == "unknown":
                    invch.new_cves.get(name)["severity"] = severity

                if invch.new_cves.get(name) != None and len(invch.new_cves.get(name)["affected_versions"]) == 0:
                    invch.new_cves.get(name)["affected_versions"] = versions
                continue

            invch.new_cves[name] = {
                "name": name,
                "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                "date": date_converted.strftime("%d.%m.%Y"),
                "keyword": keyword["keyword"].lower(),
                "description": description,
                "severity": severity,
                "affected_versions": versions,
            }


def retrieve_versions(child, keyword):
    versions = []

    for node_data in child:
        if node_data["operator"] == "AND":
            retrieve_versions(node_data["children"], keyword)

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
