from datetime import timedelta

class Constants:
    cve_file_path = "json/cves.json"
    interval = timedelta(days=30)
    inventory_file_path = "json/inventory_list.json"

    mitre_cve_url = 'https://cve.mitre.org/data/downloads/allitems.xml'