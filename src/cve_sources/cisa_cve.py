from datetime import datetime
from operator import contains
import requests
import re
from prometheus_client import Gauge
from constants import Constants
from cve_sources.abstract_cve_source import CVESource
from utils.severity_util import SeverityUtil

class CisaCVEs(CVESource):
    STATUS_REPORT = Gauge('invch_cisa', 'CISA CVE source available in Inventory Checker')
    NAME = "CISA"

    @staticmethod
    def fetch_cves(invch):
        response = requests.get(Constants.CISA_CVE_URL)
        if response.status_code != 200:
            print(f"Failed to fetch CISA CVEs, status: {response.status_code}")
            return
        root: dict = requests.get(Constants.CISA_CVE_URL).json()

        for child in root["vulnerabilities"]:
            date: str = child["dateAdded"]
            date_converted: datetime = datetime.strptime(date, "%Y-%m-%d")

            if date_converted.timestamp() < invch.start_date.timestamp():
                continue

            name: str = child["cveID"]
            description: str = child["shortDescription"].lower()

            product: str = child["product"].lower()
            vendor_project: str = child["vendorProject"].lower()
            vulnerability_name: str = child["vulnerabilityName"].lower()

            
            matched_package = next(
                (pkg for pkg in invch.packages if re.search(rf'\b{re.escape(pkg["keyword"].lower())}\b', vendor_project)),
                False
            )

            
            matched_keyword = next(
                (key for key in invch.inventory if key["keyword"].lower() in product or key["keyword"].lower() in vendor_project),
                False
            )

            if matched_package:
                matched_entry = matched_package
                matched_type = "package"
            elif matched_keyword:
                matched_entry = {"keyword": matched_keyword["keyword"], "version": "unknown"}  
                matched_type = "image"
            else:
                continue  

            
            if contains(invch.saved_cves.keys(), name):
                if contains(invch.saved_cves[name].keys(), "notAffected"):
                    continue  

            
            severity = "unknown"
            if "classification" in child and child["classification"] is not None:
                severity = SeverityUtil.getUniformSeverity(child["classification"])

            
            exit_flag = False
            for cve in invch.saved_cves.keys():
                if contains(invch.saved_cves.keys(), cve) or contains(invch.new_cves.keys(), cve):
                    if invch.new_cves.get(name) is not None and invch.new_cves.get(name)["severity"] == "unknown":
                        invch.new_cves.get(name)["severity"] = severity
                    exit_flag = True
                    break

            if exit_flag:
                continue # duplicate 

            
            invch.new_cves[name] = {
                "name": name,
                "url": f"https://nvd.nist.gov/vuln/detail/{name}",
                "date": date_converted.strftime("%d.%m.%Y"),
                "keyword": matched_entry["keyword"],
                "description": description,
                "severity": severity,
                "affected_versions": [matched_entry["version"]] if matched_entry.get("version") else [],
                "type": matched_type,
                "fromDB": "CISA"
            }

            

        
        
