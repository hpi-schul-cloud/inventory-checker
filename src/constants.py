from datetime import timedelta


class Constants:
    LOG_DIR_PATH = "src/logs"
    CVE_FILE_PATH = LOG_DIR_PATH + "/cves.json"
    VERSION_FILE_PATH = LOG_DIR_PATH + "/versions.json"
    INTERVAL = timedelta(days=5)
    PACKAGE_SOURCE = "APT"
    SCHEDULER_INTERVAL = 5
    INVENTORY_FILE_PATH = "src/json/inventory_list.json"
    PROMETHEUS_PORT = 9000
    ROCKETCHAT_WEBHOOK = None
    REPO_CREDENTIALS = {}
    GRAFANA_TOKEN = ""
    GRAFANA_HOST = ""
    GRAFANA_PROMETHEUS_UID=""
    JIRA_HOST=None
    JIRA_TOKEN=None
    JIRA_PROJECT_ID=None
    JIRA_ISSUE_TYPE="Bug"
    JIRA_USER=None
    JIRA_PRIORITY={
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "unknown": "Medium"
    }
    KEYWORD_FILTER=["controller"]
    ADDITIONAL_KEYWORDS=[]
    IGNORED_IMAGES_REPO=["harbor.infra.cluster.ionos.com"]

    # CVE Source URLs
    CISA_CVE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    VULDB_CVE_URL = "https://vuldb.com/?rss.recent"
    CERT_CVE_URL = "https://wid.cert-bund.de/content/public/securityAdvisory?size=100000000&sort=published%2Cdesc&aboFilter=false"
