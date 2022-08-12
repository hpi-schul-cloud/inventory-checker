from datetime import timedelta, timezone, datetime
from genericpath import exists
import json
import logging
import sys
import time
from constants import Constants
from cve_sources.mitre_cve import MitreCVE

class InventoryChecker:
    def run(self):
        logging.basicConfig(level = logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
        logging.info('Loading keywords...')
        inventory = self.load_inventory()

        logging.info(f'Looking for: {inventory}')
        logging.info(f'within last {Constants.interval}')
        print()

        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        local_timezone = timezone(timedelta(seconds=offset))
        now = datetime.now(local_timezone)
        start_date = now - Constants.interval

        # Load old CVEs for no duplications
        saved_cves = self.load_cves()

        new_cves = {}

        # Fetch new CVEs from different sources
        mitre_cves = MitreCVE(saved_cves, now, start_date, inventory, new_cves).fetch_cves()
        new_cves.update(mitre_cves)

        self.save_cves(saved_cves, new_cves)
        new_cve_size = len(new_cves)

        if new_cve_size == 0:
            logging.info(f'No new CVE\'s within last {Constants.interval}')
            sys.exit(0)

        logging.warning(f"{new_cve_size} new CVE's within last {Constants.interval}")
        for cve in new_cves.values():
            logging.warning(f"{cve}")
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


if __name__ == '__main__':
    InventoryChecker().run()