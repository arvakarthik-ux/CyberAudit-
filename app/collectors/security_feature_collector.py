from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class SecurityFeatureCollector(BaseCollector):
    name = "security_features"

    def collect(self) -> CollectorResult:
        script = r"$u=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA; $sb=Confirm-SecureBootUEFI -ErrorAction SilentlyContinue; Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,ProtectionStatus | ConvertTo-Json -Compress"
        result = powershell_json(script)
        if result.status == "success":
            result.data["note"] = "UAC and Secure Boot may be unavailable on some Windows editions or firmware."
        return result
