from pathlib import PureWindowsPath

from app.analyzers.base import BaseAnalyzer
from app.analyzers.configuration_analyzer import finding


class ProcessAnalyzer(BaseAnalyzer):
    def analyze(self, collected: dict) -> list[dict]:
        results = []
        connections = collected.get("network", {}).get("connections", [])
        network_pids = {c.get("pid") for c in connections if c.get("remote")}
        for p in collected.get("processes", {}).get("processes", []):
            path = (p.get("path") or "").lower()
            # AppData\\Local\\Programs is a normal per-user installation location for tools
            # such as VS Code and Python. Restrict the heuristic to transient or less expected paths.
            unusual = any(part in path for part in ("\\appdata\\local\\temp\\", "\\downloads\\", "\\appdata\\roaming\\", "\\windows\\temp\\"))
            if unusual and p.get("pid") in network_pids:
                indicators = ["Executable is running from a user-writable location.", "Process has observed external network activity."]
                results.append(finding(f"Process review recommended: {p['name']}", "Process", 55,
                    "Multiple transparent indicators warrant administrator review; this is not a malware determination.",
                    {"process": p, "indicators": indicators}, "A user-writable executable with network activity deserves validation.",
                    "Verify publisher, expected function, and startup configuration before taking any action."))
        return results
