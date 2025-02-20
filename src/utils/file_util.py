from __future__ import annotations
from typing import TYPE_CHECKING
import logging
import os

if TYPE_CHECKING:
    from inventory_checker import InventoryChecker

import json
from datetime import datetime
from pathlib import Path
from constants import Constants
from genericpath import exists


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


def save_cves(invch: InventoryChecker):
    file = open(Constants.CVE_FILE_PATH, "w")
    invch.saved_cves.update(invch.new_cves)
    file.write(json.dumps(invch.saved_cves))
    file.close()


def save_versions(invch: InventoryChecker):
    file = open(Constants.VERSION_FILE_PATH, "w")
    invch.saved_versions = invch.saved_versions + invch.new_versions
    file.write(json.dumps(invch.saved_versions))
    file.close()
