import logging
from operator import contains

import requests
from dxf import DXF, exceptions

from constants import Constants
from notifier import Notifier
from utils.file_util import FileUtil


class VersionChecker:
    def check_versions(self):
        # Load old Versions for no duplications
        self.saved_versions = FileUtil.load_versions(self)
        messages = []

        for image_full in self.images:
            host = image_full[: image_full.find("/")]
            image_nr = image_full.removeprefix(host + "/")
            image = image_nr.split(":")[0]
            tag = image_nr.split(":")[1]

            if host == "docker.io":
                host = "registry-1.docker.io"

            registry = DXF(host, image, auth)

            currentHash = None
            latestHash = None

            try:
                currentHash = registry._get_dcd(tag)
            except exceptions.DXFUnauthorizedError:
                message = 'Credentials for repo "' + host + '" are missing or are wrong!'
                if VersionChecker.containsMessage(self, message):
                    continue

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
                if VersionChecker.containsMessage(self, message):
                    continue

                messages.append(message)
                logging.warning(message)

            isNewest = currentHash == latestHash

            if not isNewest:
                message = image_nr + " has a newer version!"
                if VersionChecker.containsMessage(self, message):
                    continue

                messages.append(message)
                logging.warning(message)

        logging.info("Found " + str(len(messages)) + " version mismatches or issues!")

        if len(messages) != 0:
            logging.info("Posting version info message...")
            data = {
                "text": "Version Check",
                "attachments": list(map(lambda message: {"title": message, "color": "warning"}, messages)),
            }
            Notifier.post_message(data)

            self.new_versions = list(map(lambda message: {"message": message, "date": self.now.strftime("%d.%m.%Y")}, messages))
            FileUtil.save_versions(self)

    
    def containsMessage(self, message):
        for version in self.saved_versions:
            if version["message"] == message:
                return True
        
        return False


def auth(dxf: DXF, response):
    if contains(Constants.REPO_CREDENTIALS.keys(), dxf._host):
        credential = Constants.REPO_CREDENTIALS.get(dxf._host)
        dxf.authenticate(
            credential["username"], credential["password"], response=response
        )
