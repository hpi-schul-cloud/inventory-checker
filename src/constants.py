from datetime import timedelta


class Constants:
    CVE_FILE_PATH = "src/json/cves.json"
    INTERVAL = timedelta(days=30)
    SCHEDULER_INTERVAL = 1000 * 60 * 60
    INVENTORY_FILE_PATH = "src/json/inventory_list.json"
    PROMETHEUS_PORT = 9000
    ROCKETCHAT_WEBHOOK = None

    # CVE Source URLs
    CISA_CVE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0/"
    VULDB_CVE_URL = "https://vuldb.com/?rss.recent"
    CERT_CVE_URL = "https://wid.cert-bund.de/content/public/securityAdvisory?size=100000000&sort=published%2Cdesc&aboFilter=false"
