import json
import logging
from datetime import datetime
from pathlib import Path

from constants import Constants
from genericpath import exists

from inventory_checker import InventoryChecker


def load_versions():
    if not exists(Constants.VERSION_FILE_PATH):
        return []

    file = open(Constants.VERSION_FILE_PATH)
    s = file.read()
    file.close()

    if s == "":
        return []

    return json.loads(s)


def load_cves(invch: InventoryChecker):
    if not exists(Constants.CVE_FILE_PATH):
        invch.initial_cve_fetching = True
        return {}

    file = open(Constants.CVE_FILE_PATH)
    s = file.read()
    file.close()

    if s == "":
        return {}

    return json.loads(s)


def create_log_dir():
    if not exists(Constants.LOG_DIR_PATH):
        Path(Constants.LOG_DIR_PATH).mkdir(parents=True, exist_ok=True)


def clean_old_cves(invch: InventoryChecker):
    cve_list = load_cves(invch).values()
    if len(cve_list) == 0:
        return

    invch.new_cves = {}

    for cve in cve_list:
        if (
                datetime.strptime(cve["date"], "%d.%m.%Y").timestamp()
                >= invch.start_date.timestamp() - 60 * 60 * 24
        # need to subtract 1 day or else the invch might be stuck in a cve posting loop for 1 day
        ):
            invch.new_cves[cve["name"]] = cve

    invch.saved_cves = {}
    save_cves(invch)

    logging.info(f"Cleaned {len(cve_list) - len(invch.new_cves)} CVE's!")


def save_cves(invch: InventoryChecker):
    file = open(Constants.CVE_FILE_PATH, "w")
    invch.saved_cves.update(invch.new_cves)
    file.write(json.dumps(invch.saved_cves))
    file.close()


def clean_old_versions(invch: InventoryChecker):
    version_list = load_versions()
    if len(version_list) == 0:
        return

    invch.new_versions = []

    for version in version_list:
        if (
                datetime.strptime(version["date"], "%d.%m.%Y").timestamp()
                >= invch.start_date.timestamp()
        ):
            invch.new_versions.append(version)

    invch.saved_versions = []
    save_versions(invch)

    logging.info(f"Cleaned {len(version_list) - len(invch.new_versions)} Versions!")


def save_versions(invch: InventoryChecker):
    file = open(Constants.VERSION_FILE_PATH, "w")
    invch.saved_versions = invch.saved_versions + invch.new_versions
    file.write(json.dumps(invch.saved_versions))
    file.close()
