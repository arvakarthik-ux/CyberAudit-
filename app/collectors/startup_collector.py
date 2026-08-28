from pathlib import Path

from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import is_windows, powershell_json


class StartupCollector(BaseCollector):
    name = "startup"

    def collect(self) -> CollectorResult:
        if not is_windows():
            return CollectorResult("unsupported", message="Windows startup locations are unsupported on this OS.")
        folder = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        result = powershell_json(r"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Select-Object * -ExcludeProperty PS* | ConvertTo-Json -Compress")
        return CollectorResult("success", {"startup_folder": [str(p) for p in folder.glob("*") if p.is_file()],
                                            "registry_run": result.data.get("items", []) if result.status == "success" else [],
                                            "registry_status": result.status})
