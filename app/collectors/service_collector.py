from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class ServiceCollector(BaseCollector):
    name = "services"

    def collect(self) -> CollectorResult:
        return powershell_json("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Compress")
