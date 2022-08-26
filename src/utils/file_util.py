import json
import logging
from datetime import datetime
from operator import contains
from pathlib import Path

from constants import Constants
from genericpath import exists
from prometheus_client import Info

from utils.grafana_fetcher import GrafanaFetcher


class FileUtil:
    def load_cves(self):
        if not exists(Constants.CVE_FILE_PATH):
            return {}

        file = open(Constants.CVE_FILE_PATH)
        s = file.read()
        file.close()

        if s == "":
            return {}

        return json.loads(s)

    def load_versions(self):
        if not exists(Constants.VERSION_FILE_PATH):
            return {}

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

        self.new_cves = {}

        for cve in cve_list:
            for versions in cve["affected_versions"]:
                AFFECTED_PRODUCT_VERSIONS = Info(
                    "affected_product_versions_"
                    + cve["name"].replace("-", "_")
                    + versions.replace("-", "_").replace(".", "_"),
                    "The affected versions per product",
                )
                AFFECTED_PRODUCT_VERSIONS.clear()

            if (
                datetime.strptime(cve["date"], "%d.%m.%Y").timestamp()
                >= self.start_date.timestamp()
            ):
                self.new_cves[cve["name"]] = cve

        self.saved_cves = {}
        FileUtil.save_cves(self)

        logging.info(f"Cleaned {len(cve_list) - len(self.new_cves)} CVE's!")

    def clean_old_versions(self):
        version_list = FileUtil.load_versions(self)

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
