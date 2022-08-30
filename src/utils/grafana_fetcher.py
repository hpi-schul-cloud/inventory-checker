from operator import contains

import requests
from constants import Constants


class GrafanaFetcher:
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

    def load_inventory(self):
        response = GrafanaFetcher.fetch_prometheus_data()

        self.images = []
        images = []

        for frame in response["results"]["A"]["frames"]:
            if contains(frame["schema"]["fields"][1]["labels"].keys(), "image"):
                namespace = frame["schema"]["fields"][1]["labels"]["namespace"]
                image = frame["schema"]["fields"][1]["labels"]["image"]

                if not contains(self.images, image):
                    self.images.append(image)

                    if not namespace.startswith("kube"):
                        if not contains(image, "kube-"):
                            images.append(image)

        keywords = []

        for image_full in images:
            repo = image_full[: image_full.find("/")]
            image_nr = image_full.removeprefix(repo + "/")
            image = image_nr.split(":")[0]
            image_version = image_nr.split(":")[1]

            image_splitted = image.split("/")

            if not contains(list(map(lambda e: e["keyword"], keywords)), image_splitted[1]):
                keywords.append({
                    "keyword": image_splitted[1],
                    "version": image_version
                })

        return keywords
