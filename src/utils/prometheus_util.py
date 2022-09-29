from enum import Enum
import logging
import json

from prometheus_client import Info, start_http_server
from constants import Constants


class PrometheusUtil:
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


class Status:
    INVCH_STATUS = Info(
        "invch_status",
        "Status of the invch components",
    )

    class Component(Enum):
        grafana = "grafana_available"
        initial_fetch = "initial_cve_fetch_successfull"
        nvd = "nvd_available"
        cisa = "cisa_available"
        cert = "cert_bund_available"
        rocketchat = "rocketchat_available"
        jira = "jira_available"

    def __init__(self) -> None:
        self.status = {}
        # Set default values
        for element in Status.Component:
            self.status[element.value] = "-"

    def set_component_success(self, component: Component, state: bool):
        self.status[component.value] = str(state)

    def send_status(self):
        Status.INVCH_STATUS.info(self.status)
