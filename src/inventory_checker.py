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
from cve_sources.cert_cve import CertCVEs
from cve_sources.cisa_cve import CisaCVEs
from cve_sources.nvd_cve import NvdCVEs
import notifier
import utils.file_util as file_util
import utils.grafana_fetcher as grafana_fetcher
import utils.jira_util as jira_util
import utils.prometheus_util as prometheus_util
import version_checker


class InventoryChecker:
    REQUEST_TIME = Summary("request_processing_seconds", "Time spent processing request")
    STATUS_GRAFANA = Gauge('invch_grafana', 'Success of fetching inventory from grafana in Inventory Checker')
    STATUS_INITIAL_FETCH = Gauge('invch_initial_fetch', 'Initial CVE fetching in Inventory Checker completed')

    @REQUEST_TIME.time()
    def run(self):

        self.offset = (
            time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        )
        self.local_timezone = timezone(timedelta(seconds=self.offset))
        self.now = datetime.now(self.local_timezone)
        self.start_date = self.now - Constants.INTERVAL
        logging.info("---------------------------------------------------------------")
        logging.info("Creating log directory...")
        # TODO: Catch Exception
        file_util.create_log_dir()
        logging.info("---------------------------------------------------------------")
        logging.info("Loading keywords and versions...")
        try:
            self.inventory = grafana_fetcher.load_inventory(self)
            InventoryChecker.STATUS_GRAFANA.set(1)
        except Exception as e:
            logging.error("Loading inventory from grafana failed, skipping this run.")
            logging.exception(e)
            InventoryChecker.STATUS_GRAFANA.set(0)
            return

        logging.info("---------------------------------------------------------------")
        logging.info("Cleaning old CVE's...")
        # TODO: Catch Exception
        file_util.clean_old_cves(self)

        logging.info("---------------------------------------------------------------")
        logging.info("Cleaning old Versions's...")
        # TODO: Catch Exception
        file_util.clean_old_versions(self)

        logging.info("---------------------------------------------------------------")
        logging.info("Clearing prometheus...")
        # TODO: Catch Exception ???
        self.clear_prometheus()

        logging.info("---------------------------------------------------------------")
        logging.info(f"Looking for: {self.inventory}")
        logging.info(f"within last {Constants.INTERVAL.days} days")
        logging.info("---------------------------------------------------------------")


        logging.info("Load old CVEs for no duplications:")
        # TODO: Catch Exception
        self.saved_cves = file_util.load_cves(self)

        if (len(self.saved_cves) == 0):
            logging.warning(f"No old CVE's found.")
        else:
            for cve in self.saved_cves.values():
                logging.warning(f"From File: {cve}")

        logging.info("---------------------------------------------------------------")
        self.new_cves = {}

        partial_fetching_failure = False

        # VuldbCVE no longer used because it is chargeable. The CVE's are also displayed in NVD.
        sources = [CisaCVEs, CertCVEs, NvdCVEs]

        for source in sources:
            if not source.try_fetching_cves(self):
                partial_fetching_failure = True

        new_cve_size = len(self.new_cves)

        # Don't post new cve's because it would spam quiet a lot
        # if not hasattr(self, "initial_cve_fetching"):
            # Initial fetch already done
        InventoryChecker.STATUS_INITIAL_FETCH.set(1)
        if new_cve_size == 0:
            logging.info(f"No new CVE's within last {Constants.INTERVAL.days} days")
            number_of_failed_ticket_creations = sum(contains(saved_cve['error_creating_jira_ticket']) for saved_cve in self.saved_cves.values())
            if not number_of_failed_ticket_creations == 0:
                logging.info("Creating failed Jira Tickets")
                jira_util.create_jira_issues(self)

        else:
            logging.warning(
                f"{new_cve_size} new CVE's within last {Constants.INTERVAL.days} days"
            )
            for cve in self.new_cves.values():
                logging.warning(f"New CVE: {cve}")
                logging.info("")

            logging.info("Posting new CVE's...")
            notifier.post_cve(self.new_cves)
            jira_util.create_jira_issues(self)
        # else:
        #     data = {"text": "Connected new Instance"}
        #     Notifier.post_message(data)
        #     if partial_fetching_failure:
        #         InventoryChecker.STATUS_INITIAL_FETCH.set(0)
        #         logging.warning("Couldn't fetch from all CVE sources in first run. Not saving CVEs to avoid "
        #                         f"duplicate entries. Trying again in {Constants.SCHEDULER_INTERVAL} minutes.")
        #     else:
        #         InventoryChecker.STATUS_INITIAL_FETCH.set(1)
        #         logging.info("Skipping because it's the first time starting up...")
        #         for cve in self.new_cves.values():
        #             self.new_cves[cve["name"]]["notAffected"] = True

        # save new cves
        
        # TODO: Catch Exception
        file_util.save_cves(self)

        jira_util.check_jira_issues(self)

        self.update_prometheus()
        try:
            version_checker.check_versions(self)
        except Exception as e:
            logging.error("Checking versions failed with unexpected exception:")
            logging.exception(e)

        logging.info("")
        logging.info("=======================")
        logging.info("")

    def clear_prometheus(self):
        names = list(REGISTRY._names_to_collectors.keys())
        for name in names:
            if name.startswith("affected_product_versions_") or name.startswith("cve"):
                collector = REGISTRY._names_to_collectors.get(name)
                if collector != None:
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
                        + versions.replace(" - ", "_").replace(".", "_"),
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

        if os.getenv("GRAFANA_TOKEN"):
            Constants.GRAFANA_TOKEN = os.getenv("GRAFANA_TOKEN")
            logging.info("GRAFANA_TOKEN loaded")
        else:
            logging.info("GRAFANA_TOKEN not available")
        
        if os.getenv("GRAFANA_HOST"):
            Constants.GRAFANA_HOST = os.getenv("GRAFANA_HOST")
            logging.info("GRAFANA_HOST loaded = "+ Constants.GRAFANA_HOST)
        else:
            logging.info("GRAFANA_HOST not available")
        
        if os.getenv("GRAFANA_PROMETHEUS_UID"):
            Constants.GRAFANA_PROMETHEUS_UID = os.getenv("GRAFANA_PROMETHEUS_UID")
            logging.info("GRAFANA_PROMETHEUS_UID loaded ")
        else:
            logging.info("GRAFANA_PROMETHEUS_UID not available")

        if os.getenv("ROCKETCHAT_WEBHOOK"):
            Constants.ROCKETCHAT_WEBHOOK = os.getenv("ROCKETCHAT_WEBHOOK")
            logging.info("ROCKETCHAT_WEBHOOK loaded = " + Constants.ROCKETCHAT_WEBHOOK)
        else:
            logging.info("ROCKETCHAT_WEBHOOK not available")

        if os.getenv("SCHEDULER_INTERVAL"):
            Constants.SCHEDULER_INTERVAL = int(os.getenv("SCHEDULER_INTERVAL"))
            logging.info("SCHEDULER_INTERVAL loaded = " + str(Constants.SCHEDULER_INTERVAL))
        else:
            logging.info("SCHEDULER_INTERVAL not available")

        if os.getenv("INTERVAL"):
            Constants.INTERVAL = timedelta(days=int(os.getenv("INTERVAL")))
            logging.info("INTERVAL loaded")
        else:
            logging.info("INTERVAL not available")

        if os.getenv("PROMETHEUS_PORT"):
            Constants.PROMETHEUS_PORT = timedelta(
                days=int(os.getenv("PROMETHEUS_PORT"))
            )
            logging.info("PROMETHEUS_PORT loaded = " + str(Constants.PROMETHEUS_PORT))
        else:
            logging.info("PROMETHEUS_PORT not available")

        if os.getenv("REPO_CREDENTIALS"):
            Constants.REPO_CREDENTIALS = json.loads(os.getenv("REPO_CREDENTIALS"))
            logging.info("REPO_CREDENTIALS loaded")
        else:
            logging.info("REPO_CREDENTIALS not available")

        if os.getenv("JIRA_ISSUE_TYPE"):
            Constants.JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE")
            logging.info("JIRA_ISSUE_TYPE loaded = "+ Constants.JIRA_ISSUE_TYPE)
        else:
            logging.info("JIRA_ISSUE_TYPE not available")
        
        if os.getenv("JIRA_PRIORITY"):
            Constants.JIRA_PRIORITY = json.loads(os.getenv("JIRA_PRIORITY"))
            logging.info(f"JIRA_PRIORITY loaded = {Constants.JIRA_PRIORITY}")
        else:
            logging.info("JIRA_PRIORITY not available")

        if os.getenv("JIRA_HOST"):
            Constants.JIRA_HOST = os.getenv("JIRA_HOST")
            logging.info("JIRA_HOST loaded = "+ Constants.JIRA_HOST)
        else:
            logging.info("JIRA_HOST not available")

        if os.getenv("JIRA_TOKEN"):
            Constants.JIRA_TOKEN = os.getenv("JIRA_TOKEN")
            logging.info("JIRA_TOKEN loaded")
        else:
            logging.info("JIRA_TOKEN not available")

        if os.getenv("JIRA_PROJECT_ID"):
            Constants.JIRA_PROJECT_ID = os.getenv("JIRA_PROJECT_ID")
            logging.info("JIRA_PROJECT_ID loaded = "+ Constants.JIRA_PROJECT_ID)
        else:
            logging.info("JIRA_PROJECT_ID not available")

        if os.getenv("JIRA_USER"):
            Constants.JIRA_USER = os.getenv("JIRA_USER")
            logging.info("JIRA_USER loaded = " + Constants.JIRA_USER)
        else:
            logging.info("JIRA_USER not available")

        if os.getenv("KEYWORD_FILTER"):
            Constants.KEYWORD_FILTER = json.loads(os.getenv("KEYWORD_FILTER"))
            logging.info("KEYWORD_FILTER loaded = " + str(Constants.KEYWORD_FILTER))
        else:
            logging.info("KEYWORD_FILTER not available")

        if os.getenv("ADDITIONAL_KEYWORDS"):
            Constants.ADDITIONAL_KEYWORDS = json.loads(os.getenv("ADDITIONAL_KEYWORDS"))
            logging.info("ADDITIONAL_KEYWORDS loaded: =" + str(Constants.ADDITIONAL_KEYWORDS))
        else:
            logging.info("ADDITIONAL_KEYWORDS not available")

        prometheus_util.init_prometheus()

        schedule.every(Constants.SCHEDULER_INTERVAL).minutes.do(lambda: InventoryChecker().run())
        schedule.run_all()

        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Exiting...")
        sys.exit(0)
