from datetime import datetime
from operator import contains
import requests
from prometheus_client import Gauge

from constants import Constants
from cve_sources.abstract_cve_source import CVESource
from utils.severity_util import SeverityUtil
import json
import re


class CertCVEs(CVESource):
    STATUS_REPORT = Gauge('invch_cert', 'CERT CVE source available in Inventory Checker')
    NAME = "CERT-Bund"

    @staticmethod
    def fetch_cves(invch):
        root: dict = requests.get(Constants.CERT_CVE_URL).json()


        for child in root["content"]:
            if len(child["cves"]) == 0:
                continue

            date: str = child["published"]
            date_converted: datetime = datetime.fromisoformat(date)

            if date_converted.timestamp() < invch.start_date.timestamp():
                continue

            name: str = child["cves"][-1]  
            description = child["title"].lower()

            matched_package = next(
                (pkg for pkg in invch.packages if re.search(rf'\b{re.escape(pkg["keyword"].lower())}\b', description)),
                False
            )

            keyword = next(
                (key for key in invch.inventory if key["keyword"].lower() in description.lower()),
                False 
            )

            matched_docker_compose = next(
                (img for img in invch.images if (
                    img["container_name"].lower() in description or
                    img["image"].lower() in description
                )),
                False
            )

            if matched_package:
                matched_entry = matched_package
                matched_type = "package"
            elif keyword:
                matched_entry = {"keyword": keyword, "version": "unknown"}  
                matched_type = "image"
            elif matched_docker_compose:
                matched_entry = matched_docker_compose
                matched_type = "docker-compose"
            else:
               continue 

            if contains(invch.saved_cves.keys(), name):
                if contains(invch.saved_cves[name].keys(), "notAffected"):
                    continue  

            severity = "unknown"
            if child["classification"] is not None:
                severity = SeverityUtil.getUniformSeverity(child["classification"])

            exit_flag = False
            for cve in child["cves"]:
                if contains(invch.saved_cves.keys(), cve) or contains(invch.new_cves.keys(), cve):
                    if invch.new_cves.get(name) is not None and invch.new_cves.get(name)["severity"] == "unknown":
                        invch.new_cves.get(name)["severity"] = severity
                    exit_flag = True
                    break

            if exit_flag:
                continue  

            keyword_value = matched_entry.get("keyword", matched_entry.get("container_name", "unknown"))
            
            if isinstance(matched_entry["keyword"], dict):
                affected_version = matched_entry["keyword"].get("version", "unknown")
            else:
                affected_version = matched_entry.get("version", "unknown")

            print("Matched entry: ", matched_entry)

            invch.new_cves[name] = {
                "name": name,
                "url": f"https://wid.cert-bund.de/portal/wid/securityadvisory?name={child['name']}",
                "date": date_converted.strftime("%d.%m.%Y"),
                "keyword": keyword_value,
                "description": description,
                "severity": severity,
                "affected_versions": affected_version,
                "type": matched_type,
            }

            