class SeverityUtil:
    def getUniformSeverity(severityToTransform: str):
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
