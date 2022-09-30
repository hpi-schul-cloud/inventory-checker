from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from inventory_checker import InventoryChecker

import logging
from operator import contains

from constants import Constants
from jira import JIRA

import utils.file_util as file_util
from utils.severity_util import SeverityUtil


def create_jira_issues(invch: InventoryChecker):
    if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
        return

    jira = connect_jira(Constants.JIRA_HOST, Constants.JIRA_USER, Constants.JIRA_TOKEN)
    if(jira == None):
        return

    for cve in invch.new_cves.values():
        title = cve["name"] + " - " + cve["keyword"]
        versions = "???" if len(cve["affected_versions"]) == 0 else ", ".join(cve["affected_versions"])

        description = cve["description"] + "\n" + cve["url"] + "\n\nAffected versions: " + versions

        try:
            issue = jira.create_issue(project=Constants.JIRA_PROJECT_ID, summary=title, description=description, issuetype={"name": Constants.JIRA_ISSUE_TYPE}, priority={"name": SeverityUtil.transformSeverityToJiraPriority(cve["severity"])})
            invch.new_cves[cve["name"]]["issueId"] = issue.id
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

def check_jira_issues(invch: InventoryChecker):
    if not Constants.JIRA_HOST or not Constants.JIRA_TOKEN or not Constants.JIRA_USER or not Constants.JIRA_PROJECT_ID:
        logging.info("No Rocketchat message will be sent. ROCKETCHAT_WEBHOOK env. var. is not loaded.")
        return

    logging.info("Looking for solved JIRA Tickets...")

    jira = connect_jira(Constants.JIRA_HOST, Constants.JIRA_USER, Constants.JIRA_TOKEN)

    count_jira_request = 0
    count_new_solved_cves = 0
    for cve in invch.saved_cves.values():
        if contains(cve.keys(), "notAffected"):
            continue

        if not contains(cve.keys(), "issueId"):
            continue
        count_jira_request = count_jira_request +1

        try:
            issue = jira.search_issues('id = ' + cve["issueId"])
            logging.info(f"Ticket: {issue[0]} => {vars(issue[0])}")

            try:
                logging.info(f"Ticket status: {issue[0].fields.status.name}")
                logging.info("Ticket resolution: " + str(issue[0].fields.resolution))
            except Exception as e :
                logging.error(f"Ticket resolution name or ticket status does not exist")
                raise Exception(e)


            if(str(issue[0].fields.resolution) == "Done"):
                logging.info(f"Ticket {issue[0]} is Done. Mark as not affected.")
                count_new_solved_cves+=1
                # TODO:  set not anymore affected on issue
                cve["notAffected"] = True
                continue


            elif(str(issue[0].fields.resolution) == "Won't Do"):
                logging.info(f"Ticket {issue[0]} resolution is Won't Do. Mark as not affected.")
                count_new_solved_cves+=1
                # TODO:  set not anymore affekted on issue
                cve["notAffected"] = True
                continue


            elif(str(issue[0].fields.resolution) == "Duplicate"):
                logging.info(f"Ticket {issue[0]} resolution is Duplicate. Checking linked Tickets.")
                if(len(issue[0].fields.issuelinks) == 0):
                    logging.info(f"\tNo linked tickets in ticket {issue[0]}, can not be set as not affected.")
                else:
                    logging.info(f"\tLinked tickets:")
                    flag_all_tickets_behind_is_solved_by_links_are_done = True
                    flag_at_least_one_ticket_behind_is_solved_by_links_are_done = False
                    for link in issue[0].fields.issuelinks:


                        try:
                            if not hasattr(link, "inwardIssue"):
                                logging.info(f"\t\t Skipping outward link: {link.type.inward}")
                                continue


                            logging.info(f"\t\t Inward link name: {link.type.inward}")
                            logging.info(f"\t\t\tLinked ticket: {link.inwardIssue.key}")
                            logging.info(f"\t\t\t\tLinked ticket status: {link.inwardIssue.fields.status.name}")

                            if(not (link.type.inward == "is solved by" and link.inwardIssue.fields.status.name == "Done")):
                                flag_all_tickets_behind_is_solved_by_links_are_done = False
                            else:
                                flag_at_least_one_ticket_behind_is_solved_by_links_are_done = True

                        except Exception as e :
                            logging.error(f"link name, linked ticket name or linked Ticket status does not exist")
                            logging.error(f"Ticket/CVE with resolution Duplicate can not be checked if it's Done")
                            raise Exception(e)

                    if(flag_all_tickets_behind_is_solved_by_links_are_done and flag_at_least_one_ticket_behind_is_solved_by_links_are_done):
                        logging.info(f"\t All tickets behind is solved by links have the resolution done")
                        count_new_solved_cves+=1
                        cve["notAffected"] = True
                    else:
                        logging.info(f"\t Not All tickets behind is solved by links have the resolution done, or there was no is solved by link in this ticket")
                        logging.info(f"\tTicket {issue[0]}, can not be set as not affected.")

            else:
                logging.info(f"\t Resolution of Ticket {issue[0]} is not accepted, can not be set as not affected.")
                continue


        except Exception as e:
            # Might get thrown if Ticket was deleted or the auth token is not valid
            logging.error("Error while looking for solved JIRA tickets: ")
            logging.error("Ticket was deleted, the auth token is not valid or there are missing attributes in the ticket")
            logging.exception(e)
            continue

    logging.info("Checked all CVE's")
    logging.info(f"{count_jira_request} requests for Jira were made (Tickets, that were still affected)")
    logging.info(f"{count_new_solved_cves} are marked as solved in this poll")

    file_util.save_cves(invch)
