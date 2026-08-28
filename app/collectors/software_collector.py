from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class SoftwareCollector(BaseCollector):
    """Reads uninstall registry entries; does not use Win32_Product (which can modify installer state)."""
    name = "software"

    def collect(self) -> CollectorResult:
        script = "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName} | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName | ConvertTo-Json -Compress"
        return powershell_json(script, timeout=30)
