from app.analyzers.base import BaseAnalyzer
from app.analyzers.configuration_analyzer import finding


class NetworkAnalyzer(BaseAnalyzer):
    def analyze(self, collected: dict) -> list[dict]:
        findings = []
        reviewed_exposures: set[tuple[str, int]] = set()
        for connection in collected.get("network", {}).get("connections", []):
            local, state, protocol = connection.get("local") or {}, connection.get("state"), connection.get("protocol")
            port = local.get("port")
            if protocol == "TCP" and state == "LISTEN" and port in {3389, 445, 5985, 5986}:
                key = (protocol, port)
                if key in reviewed_exposures:
                    continue
                reviewed_exposures.add(key)
                service = {3389: "RDP", 445: "SMB", 5985: "WinRM", 5986: "WinRM"}[port]
                remediation = "block_inbound_smb" if port == 445 else None
                findings.append(finding(f"{service} listening port detected", "Network Exposure", 45,
                    f"A process is listening on the commonly used {service} port {port}.", connection,
                    "Remote management or file-sharing services can expand network exposure.",
                    "Confirm this service is required and restrict access with firewall and network policy.", remediation))
        return findings
