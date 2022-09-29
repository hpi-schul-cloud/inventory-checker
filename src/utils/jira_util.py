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

        countJiraRequest = 0
        for cve in self.saved_cves.values():
            if contains(cve.keys(), "notAffected"):
                continue

            if not contains(cve.keys(), "issueId"):
                continue
            countJiraRequest = countJiraRequest +1

            try:
                issueList = jira.search_issues('id = ' + cve["issueId"])
                issue = issueList[0]
                logging.info(f"Info about ticket: {issue} => {vars(issue)}")

                if not hasattr(issue, "fields.status.name"):
                    logging.error(f"Info about ticket status does not exist")

                if not hasattr(issue, "fields.resolution"):
                    logging.error(f"Info about ticket resolution does not exist")  
                elif not hasattr(issue, "fields.resolution.name"):
                        logging.error(f"Info about ticket resolution name does not exist")     
                else:
                    logging.info(f"Info about ticket resolution: {issue.fields.resolution.name}")       

                logging.info(f"Info about ticket status: {issue.fields.status.name}")
                #logging.info(f"Info about ticket resolution: {issue.fields.resolution.name}")

                # issues = jira.search_issues('status = Done AND id = ' + cve["issueId"])
                # TODO: if resolution Done -> set not anymore effekted on issue
                # TODO: if resolution Wont'do
                    # TODO:  set not anymore effekted on issue


                # TODO: if resolution Duplicate -> this
                
                
                if(len(issue.fields.issuelinks) == 0):
                    logging.info(f"\tNo linking Tickets in Ticket {issue.fields.status.name}")
                else: 
                    logging.info(f"\tInfo about linking issues")
                    for link in issue.fields.issuelinks:
                        
                        if hasattr(link, "inwardIssue"):
                            inwardIssue = link.inwardIssue
                            logging.info(f"\tinwardIssue-link: {link}, vars: {vars(link)}")
                            
                            if not hasattr(link, "type.inward"):
                                logging.error(f"link name does not exist")
                                #TODO: Fehlerabfangen
                                continue

                            if not hasattr(link, "inwardIssue.key"):
                                logging.error(f"linked Ticket name does not exist")
                                #TODO: Fehlerabfangen
                                continue

                            if not hasattr(link, "inwardIssue.fields.status.name"):
                                logging.error(f"linked Ticket status does not exist")
                                #TODO: Fehlerabfangen
                                continue
                            logging.info(f"\t\tCheck if this Ticket is Done or Discarded?")
                            logging.info(f"\t\t\tInfo about link name/type: {link.type.inward}")
                            logging.info(f"\t\t\tInfo about linked Ticket: {link.inwardIssue.key}")
                            logging.info(f"\t\t\t\tInfo about linked Ticket status: {link.inwardIssue.fields.status.name}")

                            # TODO:  if  Inward link name = is solved by  &&  linked.tiket.status name == done
                            # TODO:  set not anymore effekted on issue
                
            except Exception as e:
                # Might get thrown if Ticket was deleted or the auth token is not valid
                logging.error("Error while Looking for solved JIRA Tickets: ")
                logging.error("Ticket was deleted, the auth token is not valid or there are missing attributes in the Ticket")
                logging.exception(e)
                continue

        logging.info("Checked all CVE's") 
        logging.info(f"{countJiraRequest} requests for Jira were made (Tickets, that were still affected)")

        FileUtil.save_cves(self)
