from dataclasses import dataclass, field
from typing import List
from cyberaudit.models.finding import Finding


@dataclass
class ScanResult:
    system: dict
    findings: List[Finding] = field(default_factory=list)
    score: int = 100

    def to_dict(self):
        return {"system": self.system, "score": self.score, "findings": [f.to_dict() for f in self.findings]}
