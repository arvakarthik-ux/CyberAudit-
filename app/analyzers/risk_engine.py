from app.models.enums import Severity


WEIGHTS = {Severity.CRITICAL.value: 35, Severity.HIGH.value: 20, Severity.MEDIUM.value: 10, Severity.LOW.value: 4, Severity.INFO.value: 0}


def severity_for(score: float) -> Severity:
    if score >= 90: return Severity.CRITICAL
    if score >= 70: return Severity.HIGH
    if score >= 40: return Severity.MEDIUM
    if score >= 15: return Severity.LOW
    return Severity.INFO


def posture_score(findings: list[dict]) -> float:
    """Starts at 100 and caps each severity's aggregate impact; critical findings remain visible separately."""
    penalty = sum(WEIGHTS[f["severity"]] * min(max(f["risk_score"], 0), 100) / 100 for f in findings)
    return round(max(0, 100 - min(penalty, 100)), 0)


def posture_label(score: float) -> str:
    if score >= 90: return "Strong"
    if score >= 75: return "Good"
    if score >= 50: return "Needs Attention"
    if score >= 25: return "High Risk"
    return "Critical Risk"
