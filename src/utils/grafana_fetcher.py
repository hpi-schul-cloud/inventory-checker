from operator import contains

import requests

from constants import Constants


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
                }
            ],
            "from": "now-5m",
            "to": "now",
        },
    )

    return request.json()


def load_inventory(invch):
    response = fetch_prometheus_data()

    invch.images = []
    images = []

    for frame in response["results"]["A"]["frames"]:
        if contains(frame["schema"]["fields"][1]["labels"].keys(), "image"):
            # namespace = frame["schema"]["fields"][1]["labels"]["namespace"]
            image = frame["schema"]["fields"][1]["labels"]["image"]

            if not contains(invch.images, image):
                invch.images.append(image)

                # if not namespace.startswith("kube"):
                #    if not contains(image, "kube-"):
                images.append(image)

    keywords = []

    for image_full in images:
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
                "version": image_version
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
