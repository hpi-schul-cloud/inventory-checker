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

        jira = JiraUtil.connect_jira(Constants.JIRA_HOST, Constants.JIRA_USER, Constants.JIRA_TOKEN)
        
        # Delete following block
        projects = jira.projects()
        for v in projects:
            logging.info(f"Projekte in Jira: {v}")

        if(jira == None):
            return

        for cve in self.new_cves.values():
            title = cve["name"] + " - " + cve["keyword"]
            versions = "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])

            description = cve["description"] + "\n" + cve["url"] + "\n\nAffected versions: " + versions

            issue = jira.create_issue(project=Constants.JIRA_PROJECT_ID, summary=title, description=description, issuetype={"name": Constants.JIRA_ISSUE_TYPE}, priority={"name": SeverityUtil.transformSeverityToJiraPriority(cve["severity"])})
            self.new_cves[cve["name"]]["issueId"] = issue.id

    def connect_jira(jira_server, jira_user, jira_password):
    # Connect to JIRA. Return None on error
        try:
            logging.info("Connecting to JIRA: %s" % jira_server)
            jira_options = {'server': jira_server}
            jira = JIRA(options=jira_options, basic_auth=(jira_user, jira_password))
                                            # ^--- Note the tuple
            return jira
        except Exception as e:
            logging.error("Failed to connect to JIRA: %s" % e)
            return None

    def check_jira_issues(self):
        if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
            logging.info("No Rocketchat message will be sent. ROCKETCHAT_WEBHOOK is not loaded.")
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
            except Exception as e:
                # Might get thrown if Ticket was deleted or the auth token is not valid
                logging.error("Error while Looking for solved JIRA Tickets: ")
                logging.error("Ticket was deleted or the auth token is not valid")
                logging.exception(e)
                continue

            try:
                issues = jira.search_issues('id = ' + cve["issueId"])
                logging.info(f"Info About ticket: {issues}")
            except Exception as e:
                # Might get thrown if Ticket was deleted or the auth token is not valid
                logging.error("Error while Looking for solved JIRA Tickets: ")
                logging.error("Ticket was deleted or the auth token is not valid")
                logging.exception(e)
                continue

        FileUtil.save_cves(self)
