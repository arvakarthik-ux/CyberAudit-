from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class UpdateCollector(BaseCollector):
    name = "updates"

    def collect(self) -> CollectorResult:
        # Some Windows installations expose malformed or locale-specific InstalledOn values.
        # Do not let one such value fail the entire update check.
        script = r"$r=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'); Get-HotFix | Select-Object -First 20 HotFixID,InstalledOn,Description | Add-Member -PassThru NoteProperty pending_restart $r | ConvertTo-Json -Compress"
        result = powershell_json(script)
        if result.status == "success":
            result.data["assessment_note"] = "Installed updates are reported; this application does not infer missing updates without authoritative evidence."
        return result
