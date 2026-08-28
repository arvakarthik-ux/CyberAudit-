from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class FirewallCollector(BaseCollector):
    name = "firewall"

    def collect(self) -> CollectorResult:
        return powershell_json("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")
