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
                image_full = labels["image"]
                image_parts = image_full.split(":")
                image_name = image_parts[0]
                image_version = re.sub(r"^v|-.+", "", image_parts[1]) if len(image_parts) > 1 else "latest"

                # if image does not contain a registry, add docker.io
                if "." not in image_name.split("/")[0]:
                    image_full = f"docker.io/{image_full}"

                container_type = "docker-compose" if "container_label_com_docker_compose_project" in labels else "registry"

                images.append({
                    "image": image_full,
                    "keyword": image_name.split("/")[-1].replace("@sha256", ""),
                    "version": image_version,
                    "type": container_type,
                    "container_name": labels.get("image", "unknown"),
                    "compose_project": labels.get("container_label_com_docker_compose_project", "unknown"),
                    "compose_service": labels.get("container_label_com_docker_compose_service", "unknown"),
                })

    return images



def load_inventory(invch: InventoryChecker):
    response = fetch_prometheus_data()
    if not response:
        print("Failed to fetch inventory data from Prometheus.")
        return []

    invch.packages = extract_packages(response)
    invch.images = extract_images(response)
    docker_compose_images = []
    registry_images = []
    keywords = []

    for container in invch.images:

        if any(ignored in container["image"] for ignored in Constants.IGNORED_IMAGES_REPO):
            continue

        if container["type"] == "docker-compose":
            docker_compose_images.append(container)
        else:
            registry_images.append(container)

    keywords.extend(docker_compose_images)
    keywords.extend(registry_images)

    keywords = [
        kw for kw in keywords
        if kw["keyword"].lower() not in map(str.lower, Constants.KEYWORD_FILTER)
    ]


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
