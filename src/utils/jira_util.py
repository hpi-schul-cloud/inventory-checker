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
                issue = jira.search_issues('id = ' + cve["issueId"])
                logging.info(f"Ticket: {issue[0]} => {vars(issue)}")

                try:
                    logging.info(f"Ticket status: {issue[0].fields.status.name}")
                    logging.info(f"Ticket resolution: {issue[0].fields.resolution}")
                except KeyError as e :
                    logging.error(f"Ticket resolution name or ticket status does not exist") 
                    raise KeyError(e)

                
                if(issue[0].fields.resolution == "Done"):
                    logging.info(f"Ticket {issue[0]} is Done. Mark as not affected.")

                    # TODO:  set not anymore effekted on issue
                    continue


                # TODO: if resolution Wont'do
                    # TODO:  set not anymore effekted on issue
                
                elif(issue[0].fields.resolution == "Won't Do"):
                    logging.info(f"Ticket {issue[0]} resolution is Won't Do. Mark as not affected.")

                    # TODO:  set not anymore effekted on issue
                    continue


                # TODO: if resolution Duplicate -> this
                elif(issue[0].fields.resolution == "Duplicate"):
                    logging.info(f"Ticket {issue[0]} resolution is Duplicate. Checking linked Tickets.")

                    # TODO:  set not anymore effekted on issue
                    
                
                    if(len(issue[0].fields.issuelinks) == 0):
                        logging.info(f"\tNo linking Tickets in Ticket {issue[0].fields.status.name}, cant be set as not affected.")
                    else: 
                        logging.info(f"\tInfo about linking issues")
                        for link in issue[0].fields.issuelinks:
                            

                            try:
                                logging.info(f"\t\tCheck if this Ticket is Done or Discarded?")
                                logging.info(f"\t\t\tInfo about link name/type: {link.type.inward}")
                                logging.info(f"\t\t\tInfo about linked Ticket: {link.inwardIssue.key}")
                                logging.info(f"\t\t\t\tInfo about linked Ticket status: {link.inwardIssue.fields.status.name}")
                            except KeyError as e :
                                logging.error(f"link name, linked Ticket name or linked Ticket status does not exist")
                                logging.error(f"Ticket/CVE with resolution Duplicate cant be checked if it's Done")
                                raise KeyError(e)                        

                            # TODO:  if  Inward link name = is solved by  &&  linked.tiket.status name == done
                            # TODO:  set not anymore effekted on issue
                else:
                    logging.info(f"\t Resolution of Ticket {issue[0].fields.status.name} is not accepted, cant be set as not affected.")

                
                    if(len(issue[0].fields.issuelinks) == 0):
                        logging.info(f"\tNo linking Tickets in Ticket {issue[0].fields.status.name}, cant be set as not affected.")
                    else: 
                        logging.info(f"\tInfo about linking issues")
                        for link in issue[0].fields.issuelinks:
                            

                            try:
                                logging.info(f"\t\tCheck if this Ticket is Done or Discarded?")
                                logging.info(f"\t\t\tInfo about link name/type: {link.type.inward}")
                                logging.info(f"\t\t\tInfo about linked Ticket: {link.inwardIssue.key}")
                                logging.info(f"\t\t\t\tInfo about linked Ticket status: {link.inwardIssue.fields.status.name}")
                            except KeyError as e :
                                logging.error(f"link name, linked Ticket name or linked Ticket status does not exist")
                                logging.error(f"Ticket/CVE with resolution Duplicate cant be checked if it's Done")
                                raise KeyError(e)                        

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
