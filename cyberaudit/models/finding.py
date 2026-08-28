from dataclasses import dataclass, asdict


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    evidence: str
    recommendation: str

    def to_dict(self):
        return asdict(self)
