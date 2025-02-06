from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from inventory_checker import InventoryChecker

from operator import contains
import requests
from constants import Constants
import json
import os
import re
import time
import re


output_file = "cve_packages.prom"

# OSV API URL
OSV_API_URL = "https://api.osv.dev/v1/query"
def fetch_prometheus_data():
    request = requests.post(
        Constants.GRAFANA_HOST + "/api/ds/query",
        headers={"Authorization": "Bearer " + Constants.GRAFANA_TOKEN},
        
        json={
            "queries": [
                {
                    "refId": "A",
                    "datasource": {
                        "type": "prometheus",
                        "uid": Constants.GRAFANA_PROMETHEUS_UID,
                    },
                    "expr": "container_last_seen",
                 },
                {
                    "refId": "B",
                    "datasource": {
                        "type": "prometheus",
                        "uid": Constants.GRAFANA_PROMETHEUS_UID,
                },
                "expr": "package_info",
                },
                {
                    "refId": "C",
                    "datasource": {
                        "type": "prometheus",
                        "uid": Constants.GRAFANA_PROMETHEUS_UID,
                    },
                    "expr": "trivy_image_vulnerabilities",
                }
            ],
            "from": "now-5m",
            "to": "now",
        },
    )
    # print (json.dumps(request.json(), indent=4))
    return request.json()

def get_cves_for_package(package_name):
    headers = {"Content-Type": "application/json"}
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "Debian"
        }
    }

    try:
        response = requests.post(OSV_API_URL, headers=headers, json=payload, timeout=10)
        response.raise_for_status()  
        data = response.json()
        
        cve_list = []
        for vuln in data.get("vulns", []):
            cve_id = vuln.get("id", "unknown")
            description = vuln.get("summary", "No description available")
            
            cve_list.append({
                "cve_id": cve_id,
                "description": description
            })  
        
        return cve_list
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVEs for {package_name}: {e}")
        return []

def map_cves_from_prometheus(packages):
    """
    Maps CVEs to extracted packages and stores them in a consistent format with images.
    """
    output_file = "cve_packages.prom"
    package_cves = {}

    with open(output_file, "w", encoding="utf-8") as f:
        for package in packages:
            package_name = package["name"]
            package_version = package["version"]

            cve_list = get_cves_for_package(package_name)

            for cve in cve_list:
                if isinstance(cve, dict) and "cve_id" in cve:
                    sanitized_description = cve["description"].replace('"', "'")

                    # Store the CVE in the correct format
                    package_cves[cve["cve_id"]] = {
                        "name": cve["cve_id"],
                        "keyword": package_name,  # Consistent with images
                        "description": sanitized_description,
                        "severity": "unknown",  
                        "affected_versions": [package_version]
                    }

                    f.write(f'cve_vulnerability{{package="{package_name}", version="{package_version}", cve="{cve["cve_id"]}", description="{sanitized_description}"}} 1\n')
                else:
                    f.write(f'cve_vulnerability{{package="{package_name}", version="{package_version}", cve="none", description="No CVEs found"}} 0\n')

            time.sleep(0.2)  # Rate limiting to avoid API throttling

    return package_cves

def extract_packages(prometheus_data):
    """
    Extracts package names and versions from Prometheus data.
    """
    packages = []
    for frame in prometheus_data.get("results", {}).get("B", {}).get("frames", []):
        schema_fields = frame.get("schema", {}).get("fields", [])
        for field in schema_fields:
            labels = field.get("labels", {})
            if "name" in labels and "version" in labels:
                package_entry = {
                    'keyword': labels["name"].lower(),
                    'version': labels["version"],
                    'type': 'package'
                }
                if package_entry not in packages:
                    packages.append(package_entry)
                    # print(f"Found package: {package_entry['keyword']} {package_entry['version']}")
    return packages


def extract_images(prometheus_data):
    
    images = []
    for frame in prometheus_data.get("results", {}).get("A", {}).get("frames", []):
        schema_fields = frame.get("schema", {}).get("fields", [])
        for field in schema_fields:
            labels = field.get("labels", {})
            if "image" in labels:
                image = labels["image"]
                if image not in images:
                    images.append(image)
    return images



def map_cves_from_cert(invch, cert_cves):
    package_cves = {}

    for cve_id, cve_data in cert_cves.items():
        description = cve_data["description"].lower()
        print(f"🔍 Checking CVE: {cve_id} -> {description}")

        # Strict word-boundary matching
        matched_package = next(
            (pkg for pkg in invch.packages 
             if "keyword" in pkg and re.search(rf'\b{re.escape(pkg["keyword"].lower())}\b', description)),
            None
        )

        # Relaxed substring matching (if strict failed)
        if not matched_package:
            matched_package = next(
                (pkg for pkg in invch.packages 
                 if "keyword" in pkg and pkg["keyword"].lower() in description),
                None
            )

        print(f"🔎 Matched Package for {cve_id} -> {matched_package}")

        if matched_package:
            package_name = matched_package["keyword"]
            package_version = matched_package.get("version", "unknown")

            # CVE mit dem passenden Paket verknüpfen
            package_cves[cve_id] = {
                "name": cve_id,
                "url": cve_data["url"],
                "date": cve_data["date"],
                "keyword": package_name,  # Richtiger Paketname statt allgemeinem Keyword
                "description": cve_data["description"],
                "severity": cve_data["severity"],
                "affected_versions": [package_version] if package_version else [],
            }

    print(f"📌 Final mapped CVEs: {json.dumps(package_cves, indent=4)}")  # Debugging
    return package_cves



def load_inventory(invch: InventoryChecker):
    response = fetch_prometheus_data()
    if not response:
        print("Failed to fetch inventory data from Prometheus.")
        return []
    if not hasattr(invch, "new_cves"):
        invch.new_cves = {} 

    invch.packages = extract_packages(response)
    invch.images = extract_images(response)
    keywords = []


    file_path = "src/logs/package_cves.json"
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(invch.packages, file, indent=4)
    print(f"Found {len(invch.packages)} keywords.")
    file.close()

    for image_full in invch.images:
        repo = image_full[: image_full.find("/")]
        image_nr = image_full.removeprefix(repo + "/")
        image = image_nr.split(":")[0]
        image_version = image_nr.split(":")[1]

        image_splitted = image.split("/")

        keyword = (image_splitted[1] if len(image_splitted) == 2 else image_splitted[0]).replace("@sha256", "")

        if not contains(list(map(lambda e: e["keyword"], keywords)), keyword) and not contains(
                list(map(lambda e: e.lower(), Constants.KEYWORD_FILTER)), keyword.lower()):
            keywords.append({
                "keyword": keyword,
                "version": image_version,
                "type": "image"
            })
        

    for additional_keyword in Constants.ADDITIONAL_KEYWORDS:
        if not contains(list(map(lambda e: e["keyword"], keywords)), additional_keyword):
            keywords.append({
                "keyword": additional_keyword,
                "version": ""
            })

    for keyword in keywords:
        if "-" in keyword["keyword"]:
            keywords.append({
                "keyword": keyword["keyword"].replace("-", " "),
                "version": keyword["version"]
            })


    file_path = "src/logs/keywords.json"
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(keywords, file, indent=4)
    print(f"Found {len(keywords)} keywords.")
    file.close()
    return keywords
