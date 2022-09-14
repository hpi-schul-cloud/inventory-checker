import logging
from operator import contains

from constants import Constants
from jira import JIRA

from utils.file_util import FileUtil
from utils.severity_util import SeverityUtil


class JiraUtil:
    def create_jira_issues(self):
        if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
            return

        jira = JIRA(server=Constants.JIRA_HOST, basic_auth=(Constants.JIRA_USER, Constants.JIRA_TOKEN))

        for cve in self.new_cves.values():
            title = cve["name"] + " - " + cve["keyword"]
            versions = "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])

            description = cve["description"] + "\n" + cve["url"] + "\n\nAffected versions: " + versions

            issue = jira.create_issue(project=Constants.JIRA_PROJECT_ID, summary=title, description=description, issuetype={"name": Constants.JIRA_ISSUE_TYPE}, priority={"name": SeverityUtil.transformSeverityToJiraPriority(cve["severity"])})
            self.new_cves[cve["name"]]["issueId"] = issue.id

    def check_jira_issues(self):
        if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
            return

        logging.info("")
        logging.info("~~~~~~~~~~~~~~~~~~~~~~~")
        logging.info("")

        logging.info("Looking for solved JIRA Tickets...")

        jira = JIRA(server=Constants.JIRA_HOST, basic_auth=(Constants.JIRA_USER, Constants.JIRA_TOKEN))

        for cve in self.saved_cves.values():
            if contains(cve.keys(), "notAffected"):
                continue

            if not contains(cve.keys(), "issueId"):
                continue

            try:
                issues = jira.search_issues('status = Done AND id = ' + cve["issueId"])
                
                if len(issues) == 1:
                    self.saved_cves[cve["name"]]["notAffected"] = True
            except:
                # Might get thrown if Ticket was deleted or the auth token is not valid
                continue

        FileUtil.save_cves(self)
