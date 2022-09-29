import logging
from operator import contains

import requests
from dxf import DXF, exceptions

from constants import Constants
import notifier
import utils.file_util


def check_versions(invch):
    logging.info("")
    logging.info("~~~~~~~~~~~~~~~~~~~~~~~")
    logging.info("")

    logging.info("Checking for new versions...")
    # Load old Versions for no duplications
    invch.saved_versions = utils.file_util.load_versions()
    messages = []

    for image_full in invch.images:
        host = image_full[: image_full.find("/")]
        image_nr = image_full.removeprefix(host + "/")
        image = image_nr.split("@")[0] if contains(image_nr, "@") else image_nr.split(":")[0]
        tag = image_nr.split("@")[1] if contains(image_nr, "@") else image_nr.split(":")[1]

        if host == "docker.io":
            host = "registry-1.docker.io"

        registry = DXF(host, image, auth)

        currentHash = None
        latestHash = None

        if tag.startswith("sha"):
            currentHash = tag.split(":")[1]
        else:
            try:
                try:
                    currentHash = registry._get_dcd(tag)
                except exceptions.DXFUnauthorizedError:
                    message = 'Credentials for repo "' + host + '" are missing or are wrong!'
                    if contains_message(invch.saved_versions, message) or contains(messages, message):
                        continue

                    messages.append(message)
                    logging.warning(message)
                    continue
            except requests.exceptions.HTTPError:
                message = "Current tag not found for: " + image_full
                if contains_message(invch.saved_versions, message) or contains(messages, message):
                    continue

                messages.append(message)
                logging.warning(message)
                continue

        try:
            try:
                try:
                    latestHash = registry._get_dcd("latest")
                except exceptions.DXFUnauthorizedError:
                    message = 'Credentials for repo "' + host + '" are missing or are wrong!'
                    if contains_message(invch.saved_versions, message) or contains(messages, message):
                        continue

                    messages.append(message)
                    logging.warning(message)
                    continue
            except requests.exceptions.HTTPError:
                latestHash = registry._get_dcd("main")
        except requests.exceptions.HTTPError:
            message = "Latest tag not found for: " + image_full
            if contains_message(invch.saved_versions, message) or contains(messages, message):
                continue

            messages.append(message)
            logging.warning(message)

        isNewest = currentHash == latestHash if currentHash != None and latestHash != None else True

        if not isNewest:
            message = image_nr + " has a newer version!"
            if contains_message(invch.saved_versions, message) or contains(messages, message):
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
        notifier.post_message(data)

        invch.new_versions = list(
            map(lambda message: {"message": message, "date": invch.now.strftime("%d.%m.%Y")}, messages))
        utils.file_util.save_versions(invch)


def contains_message(saved_versions: list, message):
    for version in saved_versions:
        if version["message"] == message:
            return True

    return False


def auth(dxf: DXF, response):
    if contains(Constants.REPO_CREDENTIALS.keys(), dxf._host):
        credential = Constants.REPO_CREDENTIALS.get(dxf._host)
        dxf.authenticate(
            credential["username"], credential["password"], response=response
        )
