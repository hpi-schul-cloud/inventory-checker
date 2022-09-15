import json
import logging
from datetime import datetime
from pathlib import Path

from constants import Constants
from genericpath import exists


class FileUtil:
    def load_cves(self):
        if not exists(Constants.CVE_FILE_PATH):
            self.first_time = True
            return {}

        file = open(Constants.CVE_FILE_PATH)
        s = file.read()
        file.close()

        if s == "":
            return {}

        return json.loads(s)

    def load_versions(self):
        if not exists(Constants.VERSION_FILE_PATH):
            return []

        file = open(Constants.VERSION_FILE_PATH)
        s = file.read()
        file.close()

        if s == "":
            return []

        return json.loads(s)

    def create_log_dir(self):
        if not exists(Constants.LOG_DIR_PATH):
            Path(Constants.LOG_DIR_PATH).mkdir(parents=True, exist_ok=True)

    def save_cves(self):
        file = open(Constants.CVE_FILE_PATH, "w")
        self.saved_cves.update(self.new_cves)
        file.write(json.dumps(self.saved_cves))
        file.close()

    def save_versions(self):
        file = open(Constants.VERSION_FILE_PATH, "w")
        self.saved_versions = self.saved_versions + self.new_versions
        file.write(json.dumps(self.saved_versions))
        file.close()

    def clean_old_cves(self):
        cve_list = FileUtil.load_cves(self).values()
        if len(cve_list) == 0:
            return

        self.new_cves = {}

        for cve in cve_list:
            if (
                datetime.strptime(cve["date"], "%d.%m.%Y").timestamp()
                >= self.start_date.timestamp() - 60 * 60 * 24 # need to subtract 1 day or else the invch might be stuck in a cve posting loop for 1 day
            ):
                self.new_cves[cve["name"]] = cve

        self.saved_cves = {}
        FileUtil.save_cves(self)

        logging.info(f"Cleaned {len(cve_list) - len(self.new_cves)} CVE's!")

    def clean_old_versions(self):
        version_list = FileUtil.load_versions(self)
        if len(version_list) == 0:
            return

        self.new_versions = []

        for version in version_list:
            if (
                datetime.strptime(version["date"], "%d.%m.%Y").timestamp()
                >= self.start_date.timestamp()
            ):
                 self.new_versions.append(version)

        self.saved_versions = []
        FileUtil.save_versions(self)

        logging.info(f"Cleaned {len(version_list) - len(self.new_versions)} Versions!")
