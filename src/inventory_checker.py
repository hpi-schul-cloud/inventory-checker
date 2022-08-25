import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import schedule
from dotenv import load_dotenv
from prometheus_client import Gauge, Info, Summary, start_http_server

from constants import Constants
from cve_sources.cert_cve import CertCVE
from cve_sources.cisa_cve import CisaCVE
from cve_sources.nvd_cve import NvdCVE
from cve_sources.vuldb_cve import VuldbCVE
from notifier import Notifier
from utils.file_util import FileUtil
from utils.grafana_fetcher import GrafanaFetcher
from version_cecker import VersionChecker


class InventoryChecker:
    REQUEST_TIME = Summary(
        "request_processing_seconds", "Time spent processing request"
    )

    @REQUEST_TIME.time()
    def run(self):
        self.offset = (
            time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        )
        self.local_timezone = timezone(timedelta(seconds=self.offset))
        self.now = datetime.now(self.local_timezone)
        self.start_date = self.now - Constants.INTERVAL

        FileUtil.create_log_dir(self)

        logging.info("Loading keywords and versions...")
        self.inventory = GrafanaFetcher.load_inventory(self)

        logging.info("Cleaning old CVE's...")
        FileUtil.clean_old_cves(self)

        print()
        logging.info(f"Looking for: {self.inventory}")
        logging.info(f"within last {Constants.INTERVAL.days} days")
        print()

        # Load old CVEs for no duplications
        self.saved_cves = FileUtil.load_cves(self)

        self.new_cves = {}

        CisaCVE.fetch_cves(self)
        VuldbCVE.fetch_cves(self)
        CertCVE.fetch_cves(self)
        # Needs to be last to fetch versions of affected products
        NvdCVE.fetch_cves(self)

        # save new cves
        FileUtil.save_cves(self)
        new_cve_size = len(self.new_cves)

        self.update_prometheus(new_cve_size)

        if new_cve_size == 0:
            logging.info(f"No new CVE's within last {Constants.INTERVAL.days} days")
            print()
            print("~~~~~~~~~~~~~~~~~~~~~~~")
            print()
        else:
            logging.warning(
                f"{new_cve_size} new CVE's within last {Constants.INTERVAL.days} days"
            )
            for cve in self.new_cves.values():
                logging.warning(f"{cve}")
                print()

            Notifier.post_cve(self.new_cves)
            Notifier.create_jira_issues(self.new_cves)

            print("~~~~~~~~~~~~~~~~~~~~~~~")
            print()

        logging.info("Checking for new versions...")
        VersionChecker.check_versions(self)

        print()
        print("=======================")
        print()

    def update_prometheus(self, new_cve_size):
        CVE_GAUGE = Gauge("cves_total", "This is the count of the current cve's")
        CVE_GAUGE.set(new_cve_size)

        CVE_CRITICAL_SEVERITY_GAUGE = Gauge(
            "cves_critical",
            "This is the count of the current cve's which have a critical severity",
        )
        CVE_HIGH_SEVERITY_GAUGE = Gauge(
            "cves_high",
            "This is the count of the current cve's which have a high severity",
        )
        CVE_MEDIUM_SEVERITY_GAUGE = Gauge(
            "cves_medium",
            "This is the count of the current cve's which have a medium severity",
        )
        CVE_UNKOWN_SEVERITY_GAUGE = Gauge(
            "cves_unknown",
            "This is the count of the current cve's which have an unknown severity",
        )

        for cve in self.new_cves.values():
            for versions in cve["affected_versions"]:
                AFFECTED_PRODUCT_VERSIONS = Info(
                    "affected_product_versions_"
                    + cve["name"].replace("-", "_")
                    + versions.replace("-", "_").replace(".", "_"),
                    "The affected versions per product",
                )
                AFFECTED_PRODUCT_VERSIONS.info(
                    {
                        "affected_product": "True",
                        "cve": cve["name"],
                        "product": cve["keyword"],
                        "severity": cve["severity"],
                        "versions": versions,
                    }
                )

            match cve["severity"]:
                case "critical":
                    CVE_CRITICAL_SEVERITY_GAUGE.inc()
                case "high":
                    CVE_HIGH_SEVERITY_GAUGE.inc()
                case "medium":
                    CVE_MEDIUM_SEVERITY_GAUGE.inc()
                case "unknown":
                    CVE_UNKOWN_SEVERITY_GAUGE.inc()


if __name__ == "__main__":
    try:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s"
        )
        logging.info("Loading env variables...")
        load_dotenv()
        Constants.GRAFANA_TOKEN = os.getenv("GRAFANA_TOKEN")
        Constants.GRAFANA_HOST = os.getenv("GRAFANA_HOST")
        Constants.GRAFANA_PROMETHEUS_UID = os.getenv("GRAFANA_PROMETHEUS_UID")
        Constants.JIRA_HOST = os.getenv("JIRA_HOST")
        Constants.JIRA_TOKEN = os.getenv("JIRA_TOKEN")
        Constants.JIRA_PROJECT_ID = os.getenv("JIRA_PROJECT_ID")
        Constants.JIRA_USER = os.getenv("JIRA_USER")
        Constants.ROCKETCHAT_WEBHOOK = os.getenv("ROCKETCHAT_WEBHOOK")

        if os.getenv("SCHEDULER_INTERVAL"):
            Constants.SCHEDULER_INTERVAL = int(os.getenv("SCHEDULER_INTERVAL"))

        if os.getenv("INTERVAL"):
            Constants.INTERVAL = timedelta(days=int(os.getenv("INTERVAL")))

        if os.getenv("PROMETHEUS_PORT"):
            Constants.PROMETHEUS_PORT = timedelta(
                days=int(os.getenv("PROMETHEUS_PORT"))
            )

        if os.getenv("REPO_CREDENTIALS"):
            Constants.REPO_CREDENTIALS = json.JSONDecoder.decode(
                os.getenv("REPO_CREDENTIALS")
            )

        if os.getenv("JIRA_ISSUE_TYPE"):
            Constants.JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE")

        if os.getenv("JIRA_PRIORITY"):
            Constants.JIRA_PRIORITY = os.getenv("JIRA_PRIORITY")

        logging.info(
            "Starting prometheus on port " + str(Constants.PROMETHEUS_PORT) + "..."
        )
        start_http_server(Constants.PROMETHEUS_PORT)

        schedule.every(Constants.SCHEDULER_INTERVAL).minutes.do(InventoryChecker().run)
        schedule.run_all()

        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
