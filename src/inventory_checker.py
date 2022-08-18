import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import schedule
from dotenv import load_dotenv
from genericpath import exists
from prometheus_client import Gauge, Summary, start_http_server

from constants import Constants
from cve_sources.cert_cve import CertCVE
from cve_sources.cisa_cve import CisaCVE
from cve_sources.mitre_cve import MitreCVE
from cve_sources.nvd_cve import NvdCVE
from cve_sources.vuldb_cve import VuldbCVE
from notifier import Notifier

CVE_GAUGE = Gauge("cves_total", "This is the count of the current cve's")
class InventoryChecker:
    REQUEST_TIME = Summary('request_processing_seconds', 'Time spent processing request')

    @REQUEST_TIME.time()
    def run(self):
        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        local_timezone = timezone(timedelta(seconds=offset))
        now = datetime.now(local_timezone)
        start_date = now - Constants.INTERVAL

        logging.info("Loading keywords...")
        inventory = self.load_inventory()

        logging.info("Cleaning old CVE's...")
        self.clean_old_cves(start_date)

        print()
        logging.info(f"Looking for: {inventory}")
        logging.info(f"within last {Constants.INTERVAL.days} days")
        print()

        # Load old CVEs for no duplications
        saved_cves = self.load_cves()

        new_cves = {}

        mitre_cves = MitreCVE(
            saved_cves, now, start_date, inventory, new_cves
        ).fetch_cves()
        new_cves.update(mitre_cves)

        cisa_cves = CisaCVE(
            saved_cves, now, start_date, inventory, new_cves
        ).fetch_cves()
        new_cves.update(cisa_cves)

        nvd_cves = NvdCVE(saved_cves, now, start_date, inventory, new_cves).fetch_cves()
        new_cves.update(nvd_cves)

        vuldb_cves = VuldbCVE(saved_cves, now, start_date, inventory, new_cves).fetch_cves()
        new_cves.update(vuldb_cves)

        cert_cves = CertCVE(saved_cves, now, start_date, inventory, new_cves).fetch_cves()
        new_cves.update(cert_cves)

        # save new cves
        self.save_cves(saved_cves, new_cves)
        new_cve_size = len(new_cves)

        CVE_GAUGE.set(new_cve_size)

        if new_cve_size == 0:
            logging.info(f"No new CVE's within last {Constants.INTERVAL.days} days")
            print()
            print("=======================")
            print()
            return

        logging.warning(
            f"{new_cve_size} new CVE's within last {Constants.INTERVAL.days} days"
        )
        for cve in new_cves.values():
            logging.warning(f"{cve}")
            print()

        Notifier(new_cves)

        print("=======================")
        print()

    def load_cves(self):
        if not exists(Constants.CVE_FILE_PATH):
            return {}

        file = open(Constants.CVE_FILE_PATH)
        s = file.read()
        file.close()

        if s == "":
            return {}

        return json.loads(s)

    def load_inventory(self):
        if not exists(Constants.INVENTORY_FILE_PATH):
            return []

        file = open(Constants.INVENTORY_FILE_PATH)
        s = file.read()
        file.close()

        return json.loads(s)

    def save_cves(self, saved_cves, cves):
        file = open(Constants.CVE_FILE_PATH, "w")
        saved_cves.update(cves)
        file.write(json.dumps(saved_cves))
        file.close()

    def clean_old_cves(self, start_date: datetime):
        cve_list = self.load_cves().values()

        new_cves = {}

        for cve in cve_list:
            if datetime.strptime(cve["date"], "%d.%m.%Y").timestamp() >= start_date.timestamp():
                new_cves[cve["name"]] = cve

        self.save_cves({}, new_cves)

        logging.info(f"Cleaned {len(cve_list) - len(new_cves)} CVE's!")


if __name__ == "__main__":
    try:
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s"
        )
        logging.info("Loading env variables...")
        load_dotenv()
        if os.getenv("SCHEDULER_INTERVAL"):
            Constants.SCHEDULER_INTERVAL = int(os.getenv("SCHEDULER_INTERVAL"))

        if os.getenv("INTERVAL"):
            Constants.INTERVAL = timedelta(days=int(os.getenv("INTERVAL")))
            
        if os.getenv("PROMETHEUS_PORT"):
            Constants.PROMETHEUS_PORT = timedelta(days=int(os.getenv("PROMETHEUS_PORT")))
        
        logging.info("Starting prometheus on port " + str(Constants.PROMETHEUS_PORT) + "...")
        start_http_server(Constants.PROMETHEUS_PORT)

        schedule.every(Constants.SCHEDULER_INTERVAL).seconds.do(InventoryChecker().run)
        schedule.run_all()
        
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
