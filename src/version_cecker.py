import logging
from operator import contains

import requests
from dxf import DXF, exceptions

from constants import Constants
from notifier import Notifier


class VersionChecker:
    def check_versions(self):
        messages = []

        for image_full in self.images:
            repo = image_full[: image_full.find("/")]
            image_nr = image_full.removeprefix(repo + "/")
            image = image_nr.split(":")[0]
            tag = image_nr.split(":")[1]

            if repo == "docker.io":
                repo = "registry-1.docker.io"

            registry = DXF(repo, image, auth)

            currentHash = None
            latestHash = None

            try:
                currentHash = registry._get_dcd(tag)
            except exceptions.DXFUnauthorizedError:
                message = 'Credentials for repo "' + repo + '" are missing!'
                messages.append(message)
                logging.warning(message)
                continue

            try:
                try:
                    latestHash = registry._get_dcd("latest")
                except requests.exceptions.HTTPError:
                    latestHash = registry._get_dcd("main")
            except requests.exceptions.HTTPError:
                message = "Latest tag not found for: " + image_full
                messages.append(message)
                logging.warning(message)

            isNewest = currentHash == latestHash

            if not isNewest:
                message = image_nr + " has a newer version!"
                messages.append(message)
                logging.warning(message)

        logging.info("Found " + len(messages) + " version mismatches or issues!")

        if len(messages) != 0:
            logging.info("Posting version info message...")
            data = {
                "text": "Version Check",
                "attachments": list(map(lambda message: {"title": message, "color": "warning"}, messages)),
            }
            Notifier.post_message(data)


def auth(dxf: DXF, response):
    if contains(Constants.REPO_CREDENTIALS.keys(), dxf._repo):
        credential = Constants.REPO_CREDENTIALS.get(dxf._repo)
        dxf.authenticate(
            credential["username"], credential["password"], response=response
        )
