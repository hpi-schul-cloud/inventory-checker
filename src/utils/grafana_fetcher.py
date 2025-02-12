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
                }
            ],
            "from": "now-5m",
            "to": "now",
        },
    )
    return request.json()



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


    return keywords
