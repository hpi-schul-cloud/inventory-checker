# Inventory Checker

Tool for filtering CVEs by keywords and alerting them to jira and rocketchat. Also checks version of programs and alerts if there is a newer version available.

## What does the inventory checker provides?

- New CVEs are parsed from a CVE source and logged on stdout
- Available in Grafana **(Available as diagrams/list)**
- Filter by product to only show CVEs for products we use
- Filter by used version of used product **(Doesn't work for all CVE's because not all CVE Sources provide versions)**
- CVEs are sent with the affected product and a short description as a message in the rocketchat channel **(Implemented with Rocket Chat WebHook)**
- Creates automatically a new JIRA Ticket with priority depending on severity of the CVE
- Auto detects whether the ticket has been processed **(only if jira is activated)**

## Which CVE Sources are used?

- [CISA](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [NVD](https://services.nvd.nist.gov/rest/json/cves/1.0/) ***(The only source, that provides affected versions)***
- [VulDB](https://vuldb.com/?rss.recent)
- [CERT-Bund](https://wid.cert-bund.de/content/public/securityAdvisory?size=100000000&sort=published%2Cdesc&aboFilter=false)

## Want to add further CVE Sources?

Further CVE Sources need to be implemented manually due to inconsistent design pattern in CVE API's/RSS Feeds

## Environment Variables
The configuration variables are defined in the ansible group_vars or host_vars. Security relevant variables are defined in 1Password.
| **Environment Variable** | **Description** | **Required** | **Standard Value** | **Unit + Type** |
|-|-|-|-|-|
| **SCHEDULER_INTERVAL** | Describes how often the program fetches the CVE's in minutes | no | 60 | minutes, number
| **INTERVAL** | Describes in which date interval the CVE's are fetched | no | 30 | days, number
| **PROMETHEUS_PORT** | The prometheus port the client serves the data | no | 9000 | -, number
| **ROCKETCHAT_WEBHOOK** | The Webhook URL for the Rocketchat Bot. If not served, there will be no messages in RocketChat | no | None | -, string
| **GRAFANA_TOKEN** | The grafana api token | yes | None | -, string
| **GRAFANA_HOST** | The url of the grafana dashboard | yes | None | -, string
| **GRAFANA_PROMETHEUS_UID** | The unique ID that is shown in the url when editing the datasource | yes | None | -, string
| **JIRA_HOST** | The url of the Jira dashboard * | no | None | -, string
| **JIRA_USER** | The Jira user (that created the api token) * | no | None | -, string
| **JIRA_TOKEN** | The Jira api token or password of the user * | no | None | -, string
| **JIRA_PROJECT_ID** | The project ID e.g. "OPS" * | no | None | -, string
| **JIRA_ISSUE_TYPE** | The issue type that gets assigned to the Jira issue (not the translated form, so not "Aufgabe" but instead "Task") | no | Bug | -, string
| **JIRA_PRIORITY** | The priority that gets attached to the Jira issue (not the translated form, so not "Hoch" but instead "High")<br><br> Example: <br><br> JIRA_PRIORITY={"critical": "🚨CRITICAL🚨","high": "High","medium": "Medium","low": "Low","unknown": "Medium"} | no | {<br>"critical": "Highest",<br>"high": "High",<br>"medium": "Medium",<br>"low": "Low",<br>"unknown": "Medium"<br>} | -, string
| **REPO_CREDENTIALS** | The credentials that are needed to fetch from registries like registry-1.docker.io. Provide a password or a token as password <br><br> **Note**: use registry-1.docker.io instead of docker.io <br><br> Example: <br><br> REPO_CREDENTIALS={"registry-1.docker.io": {"username": "maxmustermann","password": "abcdef"}} | no | {} | -, string
| **GRAFANA_PROMETHEUS_UID** | This is used to filter specific keywords like "node" since it is a term that is broadly used <br><br> Example: <br><br> GRAFANA_PROMETHEUS_UID=["node", "backend"] | no | [] | -, string
| **ADDITIONAL_KEYWORDS** | This is used to add additional keywords. For example "bbb" because it can't be fetched over grafana. <br><br> Example: <br><br> ADDITIONAL_KEYWORDS=["bbb"] | no | [] | -, string

\* When using JIRA the marked ENV are required
