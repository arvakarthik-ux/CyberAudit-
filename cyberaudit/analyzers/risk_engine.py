from typing import List
from cyberaudit.models.finding import Finding


SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5}


def calculate_score(findings: List[Finding]) -> int:
    score = 100
    for f in findings:
        w = SEVERITY_WEIGHTS.get(f.severity.upper(), 0)
        score -= w
    if score < 0:
        score = 0
    return score
