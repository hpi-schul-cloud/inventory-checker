import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from operator import contains

import schedule
from dotenv import load_dotenv
from prometheus_client import REGISTRY, Gauge, Info, Summary

from constants import Constants
from cve_sources.cert_cve import CertCVE
from cve_sources.cisa_cve import CisaCVE
from cve_sources.nvd_cve import NvdCVE
from cve_sources.vuldb_cve import VuldbCVE
from notifier import Notifier
from utils.file_util import FileUtil
from utils.grafana_fetcher import GrafanaFetcher
from utils.jira_util import JiraUtil
from utils.prometheus_util import PrometheusUtil
from version_checker import VersionChecker


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

        logging.info("Cleaning old Versions's...")
        FileUtil.clean_old_versions(self)

        self.clear_prometheus()

        logging.info("")
        logging.info(f"Looking for: {self.inventory}")
        logging.info(f"within last {Constants.INTERVAL.days} days")
        logging.info("")

        # Load old CVEs for no duplications
        self.saved_cves = FileUtil.load_cves(self)

        self.new_cves = {}

        CisaCVE.fetch_cves(self)
        VuldbCVE.fetch_cves(self)
        CertCVE.fetch_cves(self)
        # Needs to be last to fetch versions of affected products
        NvdCVE.fetch_cves(self)

        new_cve_size = len(self.new_cves)

        # Don't post new cve's because it would spam quiet a lot
        if not hasattr(self, "first_time"):
            if new_cve_size == 0:
                logging.info(f"No new CVE's within last {Constants.INTERVAL.days} days")
            else:
                logging.warning(
                    f"{new_cve_size} new CVE's within last {Constants.INTERVAL.days} days"
                )
                for cve in self.new_cves.values():
                    logging.warning(f"{cve}")
                    logging.info("")

                logging.info("Posting new CVE's...")
                Notifier.post_cve(self.new_cves)
                JiraUtil.create_jira_issues(self)
        else:
            logging.info("Skipping because it's the first time starting up...")

        # save new cves
        FileUtil.save_cves(self)

        JiraUtil.check_jira_issues(self)

        self.update_prometheus()

        VersionChecker.check_versions(self)

        logging.info("")
        logging.info("=======================")
        logging.info("")

    def clear_prometheus(self):
        cleared = []

        names = list(REGISTRY._names_to_collectors.keys())
        for name in names:
            if name.startswith("affected_product_versions_") or name.startswith("cve"):
                collector = REGISTRY._names_to_collectors.get(name)
                if not contains(cleared, collector):
                    cleared.append(collector)
                    REGISTRY.unregister(collector)

    def update_prometheus(self):
        CVE_GAUGE = Gauge("cves_total", "This is the count of the current cve's")

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
        CVE_LOW_SEVERITY_GAUGE = Gauge(
            "cves_low",
            "This is the count of the current cve's which have a low severity",
        )
        CVE_UNKOWN_SEVERITY_GAUGE = Gauge(
            "cves_unknown",
            "This is the count of the current cve's which have an unknown severity",
        )

        for cve in self.saved_cves.values():
            if contains(cve.keys(), "notAffected"):
                continue

            if len(cve["affected_versions"]) == 0:
                AFFECTED_PRODUCT_VERSIONS = Info(
                        "affected_product_versions_"
                        + cve["name"].replace("-", "_")
                        + "",
                        "The affected versions per product",
                    )
                AFFECTED_PRODUCT_VERSIONS.info(
                    {
                        "affected_product": "True",
                        "cve": cve["name"],
                        "product": cve["keyword"],
                        "severity": cve["severity"],
                        "versions": "-1",
                    }
                )
            else:
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

            CVE_GAUGE.inc()

            match cve["severity"]:
                case "critical":
                    CVE_CRITICAL_SEVERITY_GAUGE.inc()
                case "high":
                    CVE_HIGH_SEVERITY_GAUGE.inc()
                case "medium":
                    CVE_MEDIUM_SEVERITY_GAUGE.inc()
                case "low":
                    CVE_LOW_SEVERITY_GAUGE.inc()
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

        if os.getenv("ROCKETCHAT_WEBHOOK"):
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
            Constants.REPO_CREDENTIALS = json.loads(os.getenv("REPO_CREDENTIALS"))

        if os.getenv("JIRA_ISSUE_TYPE"):
            Constants.JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE")

        if os.getenv("JIRA_PRIORITY"):
            Constants.JIRA_PRIORITY = json.loads(os.getenv("JIRA_PRIORITY"))

        if os.getenv("JIRA_HOST"):
            Constants.JIRA_HOST = os.getenv("JIRA_HOST")

        if os.getenv("JIRA_TOKEN"):
            Constants.JIRA_TOKEN = os.getenv("JIRA_TOKEN")

        if os.getenv("JIRA_PROJECT_ID"):
            Constants.JIRA_PROJECT_ID = os.getenv("JIRA_PROJECT_ID")

        if os.getenv("JIRA_USER"):
            Constants.JIRA_USER = os.getenv("JIRA_USER")

        PrometheusUtil.init_prometheus()

        schedule.every(Constants.SCHEDULER_INTERVAL).minutes.do(InventoryChecker().run)
        schedule.run_all()

        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Exiting...")
        sys.exit(0)