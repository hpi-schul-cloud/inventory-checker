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
        self.load_inventory()

        logging.info(f'Looking for: {self.inventory}')
        logging.info(f'within last {Constants.interval}')
        print()

        offset = time.timezone if (time.localtime().tm_isdst == 0) else time.altzone
        local_timezone = timezone(timedelta(seconds=offset))
        self.now = datetime.now(local_timezone)
        self.start_date = self.now - Constants.interval

        self.savedCves = self.load_cves()

        self.newCves = {}

        MitreCVE(self.savedCves, self.now, self.start_date, self.inventory, self.newCves)

        newCveSize = len(self.newCves)

        if newCveSize == 0:
            logging.info(f'No new CVE\'s within last {Constants.interval}')
            sys.exit(0)

        logging.warning(f"{newCveSize} new CVE's within last {Constants.interval}")

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
        file = open(Constants.inventory_file_path)
        s = file.read()
        file.close()

        self.inventory = json.loads(s)


if __name__ == '__main__':
    InventoryChecker().run()