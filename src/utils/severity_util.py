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
