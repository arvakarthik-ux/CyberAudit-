from app.analyzers.configuration_analyzer import ConfigurationAnalyzer
from app.analyzers.network_analyzer import NetworkAnalyzer
from app.analyzers.process_analyzer import ProcessAnalyzer
from app.analyzers.risk_engine import posture_score


class SecurityPostureAnalyzer:
    def analyze(self, collected: dict) -> tuple[list[dict], float]:
        findings = ConfigurationAnalyzer().analyze(collected) + NetworkAnalyzer().analyze(collected) + ProcessAnalyzer().analyze(collected)
        return findings, posture_score(findings)
