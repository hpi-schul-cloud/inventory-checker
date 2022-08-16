from datetime import timedelta


class Constants:
    cve_file_path = "json/cves.json"
    interval = timedelta(days=30)
    inventory_file_path = "json/inventory_list.json"
    prometheus_port = 9000

    # CVE Source URLs
    mitre_cve_url = "https://cve.mitre.org/data/downloads/allitems.xml"
    cisa_cve_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_cve_url = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    vuldb_cve_url = "https://vuldb.com/?rss.recent"
    cert_cve_url = "https://wid.cert-bund.de/content/public/securityAdvisory?size=100000000&sort=published%2Cdesc&aboFilter=false"
