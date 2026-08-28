from typing import Any

from app.analyzers.base import BaseAnalyzer


def finding(title: str, category: str, score: float, description: str, evidence: dict, impact: str, recommendation: str,
            remediation_id: str | None = None) -> dict[str, Any]:
    from app.analyzers.risk_engine import severity_for
    return {"title": title, "category": category, "severity": severity_for(score).value, "risk_score": score,
            "confidence": "HIGH", "status": "OPEN", "description": description, "evidence": evidence, "impact": impact,
            "recommendation": recommendation, "remediation_available": remediation_id is not None, "requires_admin": remediation_id is not None,
            "remediation_id": remediation_id}


class ConfigurationAnalyzer(BaseAnalyzer):
    def analyze(self, collected: dict[str, Any]) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        firewall = collected.get("firewall", {}).get("items", [])
        for profile in firewall:
            if profile.get("Enabled") is False:
                output.append(finding(f"Windows Firewall {profile.get('Name')} Profile Disabled", "Firewall", 80,
                    "A Windows Firewall profile reports as disabled.", profile, "The device may accept unwanted inbound traffic.",
                    "Enable the disabled firewall profile after reviewing local policy.", "enable_firewall_profile"))
        defender = collected.get("defender", {}).get("items", [])
        if defender and defender[0].get("RealTimeProtectionEnabled") is False:
            output.append(finding("Microsoft Defender real-time protection disabled", "Defender", 75,
                "Microsoft Defender reports real-time protection as disabled.", defender[0], "Threat detection coverage may be reduced.",
                "Enable real-time protection if Defender is your selected endpoint protection.", "enable_defender_realtime"))
        users = collected.get("users", {}).get("items", [])
        for user in users:
            if str(user.get("Name", "")).lower() == "guest" and user.get("Enabled") is True:
                output.append(finding("Guest account enabled", "Accounts", 70, "The built-in Guest account is enabled.", user,
                    "Guest access can increase local attack surface.", "Disable the Guest account unless its use is explicitly required.", "disable_guest_account"))
        return output
