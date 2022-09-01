from constants import Constants


class SeverityUtil:
    def getUniformSeverity(severityToTransform: str):
        # different sources have different namings for the same thing
        match severityToTransform:
            case "CRITICAL" | "very critical" | "kritisch":
                return "critical"
            case "HIGH" | "critical" | "hoch":
                return "high"
            case "MEDIUM" | "problematic" | "mittel":
                return "medium"
            case "LOW" | "niedrig":
                return "low"
            case "unknown":
                return "unknown"
            case _:
                return "none"

    def transformSeverityToJiraPriority(severityToTransform: str):
        match severityToTransform:
            case "critical":
                return Constants.JIRA_PRIORITY.get("critical")
            case "high":
                return Constants.JIRA_PRIORITY.get("high")
            case "medium":
                return Constants.JIRA_PRIORITY.get("medium")
            case "low":
                return Constants.JIRA_PRIORITY.get("low")
            case _:
                return Constants.JIRA_PRIORITY.get("unknown")
