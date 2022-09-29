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
        if(jira == None):
            return        

        for cve in self.new_cves.values():
            title = cve["name"] + " - " + cve["keyword"]
            versions = "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])

            description = cve["description"] + "\n" + cve["url"] + "\n\nAffected versions: " + versions

            try:
                issue = jira.create_issue(project=Constants.JIRA_PROJECT_ID, summary=title, description=description, issuetype={"name": Constants.JIRA_ISSUE_TYPE}, priority={"name": SeverityUtil.transformSeverityToJiraPriority(cve["severity"])})
                self.new_cves[cve["name"]]["issueId"] = issue.id
                logging.info(f"Created issue: {issue} with Ticket: {cve}")
            except Exception as e:
                logging.error("Error while creating JIRA Tickets: ")
                logging.info(f"Ticket: {cve}")
                logging.exception(e)
                continue
           

    def connect_jira(jira_server, jira_user, jira_password):
    # Connect to JIRA. Return None on error
        try:
            logging.info("Connecting to JIRA: %s" % jira_server)
            jira_options = {'server': jira_server}
            jira = JIRA(options=jira_options, basic_auth=(jira_user, jira_password))
                                            # ^--- Note the tuple
            logging.info("succsessful" )                                
            return jira
        except Exception as e:
            logging.error("Failed to connect to JIRA: %s" % e)
            return None

    def check_jira_issues(self):
        if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
            logging.info("No Rocketchat message will be sent. ROCKETCHAT_WEBHOOK env. var. is not loaded.")
            return

        logging.info("Looking for solved JIRA Tickets...")

        jira = JiraUtil.connect_jira(Constants.JIRA_HOST, Constants.JIRA_USER, Constants.JIRA_TOKEN)

        for cve in self.saved_cves.values():
            if contains(cve.keys(), "notAffected"):
                continue

            if not contains(cve.keys(), "issueId"):
                continue

            try:
                # issues = jira.search_issues('status = Done AND id = ' + cve["issueId"])
                issue = jira.search_issues('id = ' + cve["issueId"])
                logging.info(f"Info about ticket: {issue[0]} => {vars(issue[0])}")
                logging.info(f"Info about ticket status: {issue[0].fields.status.name}")
                if(len(issue[0].fields.issuelinks) == 0):
                    logging.info(f"No linking Tickets in Ticket {issue[0].fields.status.name}")
                else: 
                    logging.info(f"Info about linking issues")
                    link_counter = 1
                    for link in issue[0].fields.issuelinks:
                        
                        if hasattr(link, "inwardIssue"):
                            inwardIssue = link.inwardIssue
                            logging.info(f"inwardIssue {link_counter}, link: {link}, vars: {vars(link)}")
                            link_counter = link_counter + 1
                            # if(link[0].raw.)
                            # check name = is solved by

                            # TODO: Check if attributes are available and catch errors
                            logging.info(f"\t\tCheck if this Ticket is Done or Discarded?")
                            #logging.info(f"\t\t\tInfo about linkedIssue name: {link.raw.type.inward}")
                            logging.info(f"\t\t\tInfo about linkedIssue Ticket: {link.raw.inwardIssue.key}")
                            logging.info(f"\t\t\tInfo about linkedIssue status: {link.raw.inwardIssue.fields.status.name}")
                        



                #logging.info(f"Info About ticket.fields.status: {issue[0].fields.status}")
                
                #logging.info(f"Info About ticket.fields.comment.comments: {issue[0].fields.comment.comments}")
                #logging.info(f"Info About ticket.fields.summary: {issue[0].fields.summary}")
                #logging.info(f"Info About ticket.fields.project.key: {issue[0].fields.project.key}")
                #logging.info(f"Info About ticket.fields.reporter.displayName: {issue[0].fields.reporter.displayName}")

                
            except Exception as e:
                # Might get thrown if Ticket was deleted or the auth token is not valid
                logging.error("Error while Looking for solved JIRA Tickets: ")
                logging.error("Ticket was deleted or the auth token is not valid")
                logging.exception(e)
                continue

        logging.info("Checked all CVE's") 

        FileUtil.save_cves(self)
