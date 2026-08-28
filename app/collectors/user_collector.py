from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class UserCollector(BaseCollector):
    name = "users"

    def collect(self) -> CollectorResult:
        return powershell_json("Get-LocalUser | Select-Object Name,Enabled,LastLogon,PrincipalSource | ConvertTo-Json -Compress")
