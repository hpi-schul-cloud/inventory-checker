import requests
from jira import JIRA

from constants import Constants


class Notifier:
    def post_cve(new_cves):
        if len(new_cves) == 0 or not Constants.ROCKETCHAT_WEBHOOK:
            return

        msg = f"Found {len(new_cves)} new CVE's within last {Constants.INTERVAL.days} days:"
        attachments = []

        for cve in new_cves.values():
            date: str = cve["date"]
            keyword: str = cve["keyword"].upper()
            name: str = cve["name"]
            title: str = f"{date} | {keyword} - {name}"

            color = "warning"

            if cve["severity"] == "critical" or cve["severity"] == "high":
                color = "danger"

            attachments.append(
                {
                    "title": title,
                    "title_link": cve["url"],
                    "text": cve["description"],
                    "color": color,
                    "collapsed": True,
                    "fields": [{
                        "title": "Affected versions:",
                        "value": "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])
                    }]
                }
            )

        data = {"text": msg, "attachments": attachments}

        requests.post(Constants.ROCKETCHAT_WEBHOOK, json=data)

    def post_message(data):
        if not Constants.ROCKETCHAT_WEBHOOK:
            return

        requests.post(Constants.ROCKETCHAT_WEBHOOK, json=data)

    def create_jira_issues(new_cves):
        jira = JIRA(server=Constants.JIRA_HOST, basic_auth=(Constants.JIRA_USER, Constants.JIRA_TOKEN))

        for cve in new_cves.values():
            title = cve["name"]
            description = cve["description"]

            jira.create_issue(project=Constants.JIRA_PROJECT_ID, summary=title, description=description, issuetype={"name": Constants.JIRA_ISSUE_TYPE}, priority={"name": Constants.JIRA_PRIORITY})
