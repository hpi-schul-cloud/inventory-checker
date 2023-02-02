import logging
import json
import re

from prometheus_client import Info, start_http_server
from constants import Constants


def init_prometheus():
    logging.info(
            "Starting prometheus on port " + str(Constants.PROMETHEUS_PORT) + "..."
        )
    start_http_server(Constants.PROMETHEUS_PORT)

    INVCH_INFO = Info(
                    "invch",
                    "The InvCh ENV information",
                )
    INVCH_INFO.info(
        {
            "prometheus_port": str(Constants.PROMETHEUS_PORT),
            "scheduler_interval": str(Constants.SCHEDULER_INTERVAL),
            "interval": str(Constants.INTERVAL.days),
            "jira_project_id": "-" if Constants.JIRA_HOST == None else str(Constants.JIRA_PROJECT_ID),
            "jira_issue_type": "-" if Constants.JIRA_HOST == None else str(Constants.JIRA_ISSUE_TYPE),
            "jira_priority": "{}" if Constants.JIRA_HOST == None else json.dumps(Constants.JIRA_PRIORITY),
            "uses_rocketchat": str(True) if Constants.ROCKETCHAT_WEBHOOK != None else str(False)
        }
    )


def sanitize_string(input: str):
    """Replaces all characters except alphanumerics with an underscore to create a valid metric name"""
    return re.sub("\\W+", "_", input)