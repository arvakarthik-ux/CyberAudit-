from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class DefenderCollector(BaseCollector):
    name = "defender"

    def collect(self) -> CollectorResult:
        return powershell_json("Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled | ConvertTo-Json -Compress")
