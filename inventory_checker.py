import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

import schedule
from dotenv import load_dotenv
from genericpath import exists

from constants import Constants
from cve_sources.cert_cve import CertCVE
from cve_sources.cisa_cve import CisaCVE
from cve_sources.mitre_cve import MitreCVE
from cve_sources.nvd_cve import NvdCVE
from cve_sources.vuldb_cve import VuldbCVE
from notifier import Notifier


class InventoryChecker:
    def run(self):
        load_dotenv()
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s: %(message)s"
        )
        logging.info("Loading keywords...")
        inventory = self.load_inventory()

        logging.info(f"Looking for: {inventory}")
        logging.info(f"within last {Constants.interval.days} days")
        print()

        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        local_timezone = timezone(timedelta(seconds=offset))
        now = datetime.now(local_timezone)
        start_date = now - Constants.interval

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

        if new_cve_size == 0:
            logging.info(f"No new CVE's within last {Constants.interval.days} days")
            print()
            print("=======================")
            print()
            return

        logging.warning(
            f"{new_cve_size} new CVE's within last {Constants.interval.days} days"
        )
        for cve in new_cves.values():
            logging.warning(f"{cve}")
            print()

        Notifier(new_cves)

        print("=======================")
        print()

    def load_cves(self):
        if not exists(Constants.cve_file_path):
            return {}

        file = open(Constants.cve_file_path)
        s = file.read()
        file.close()

        if s == "":
            return {}

        return json.loads(s)

    def load_inventory(self):
        if not exists(Constants.inventory_file_path):
            return []

        file = open(Constants.inventory_file_path)
        s = file.read()
        file.close()

        return json.loads(s)

    def save_cves(self, saved_cves, cves):
        file = open(Constants.cve_file_path, "w")
        saved_cves.update(cves)
        file.write(json.dumps(saved_cves))
        file.close()


if __name__ == "__main__":
    try:
        schedule.every().hour.do(InventoryChecker().run)
        schedule.run_all()
        
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
