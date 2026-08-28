import ctypes
import platform
import subprocess
from pathlib import Path

from app.remediation.base import ActionResult, BaseRemediation


def _admin() -> bool:
    return platform.system() == "Windows" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def _run(script: str) -> ActionResult:
    if not _admin(): return ActionResult(False, "Administrator privileges are required; no change was made.")
    completed = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, check=False)
    return ActionResult(completed.returncode == 0, (completed.stdout or completed.stderr or "Command completed.").strip()[:500])


class FirewallProfileRemediation(BaseRemediation):
    action_id = "enable_firewall_profile"
    def preview(self, evidence: dict) -> dict:
        name = evidence.get("Name", "Unknown")
        return {"action": f"Enable the Windows Firewall {name} profile.", "settings_changed": ["Windows Firewall profile enabled state"], "requires_admin": True}
    def apply(self, evidence: dict) -> ActionResult:
        name = str(evidence.get("Name", ""))
        if name not in {"Domain", "Private", "Public"}: return ActionResult(False, "Unsupported firewall profile; no change was made.")
        result = _run(f"Set-NetFirewallProfile -Profile {name} -Enabled True")
        result.backup_data = {"Name": name, "Enabled": evidence.get("Enabled")}
        return result
    def rollback(self, backup_data: dict) -> ActionResult:
        name = backup_data.get("Name")
        if name not in {"Domain", "Private", "Public"}: return ActionResult(False, "Invalid rollback data.")
        return _run(f"Set-NetFirewallProfile -Profile {name} -Enabled {'True' if backup_data.get('Enabled') else 'False'}")


class DefenderRemediation(BaseRemediation):
    action_id = "enable_defender_realtime"
    def preview(self, evidence: dict) -> dict:
        return {"action": "Enable Microsoft Defender real-time monitoring.", "settings_changed": ["Defender DisableRealtimeMonitoring preference"], "requires_admin": True}
    def apply(self, evidence: dict) -> ActionResult:
        # A successful preference command is not enough: Tamper Protection, Group Policy,
        # or another endpoint product can keep real-time protection disabled.
        result = _run(
            "$ErrorActionPreference='Stop'; "
            "Set-MpPreference -DisableRealtimeMonitoring $false; "
            "Start-Sleep -Seconds 2; "
            "$status=Get-MpComputerStatus; "
            "if (-not $status.RealTimeProtectionEnabled) { "
            "Write-Error 'Microsoft Defender still reports real-time protection as disabled. It may be managed by Tamper Protection, Group Policy, or another antivirus product.'; exit 1 }; "
            "Write-Output 'Microsoft Defender real-time protection is enabled and verified.'"
        )
        result.backup_data = {"RealTimeProtectionEnabled": evidence.get("RealTimeProtectionEnabled")}
        return result
    def rollback(self, backup_data: dict) -> ActionResult:
        if backup_data.get("RealTimeProtectionEnabled") is not False: return ActionResult(False, "Rollback is not required for the recorded state.")
        return _run("Set-MpPreference -DisableRealtimeMonitoring $true")


class GuestAccountRemediation(BaseRemediation):
    action_id = "disable_guest_account"
    def preview(self, evidence: dict) -> dict:
        return {"action": "Disable the built-in Guest account.", "settings_changed": ["Local Guest account enabled state"], "requires_admin": True}
    def apply(self, evidence: dict) -> ActionResult:
        result = _run("Disable-LocalUser -Name 'Guest'")
        result.backup_data = {"Name": "Guest", "Enabled": evidence.get("Enabled")}
        return result
    def rollback(self, backup_data: dict) -> ActionResult:
        return _run("Enable-LocalUser -Name 'Guest'") if backup_data.get("Enabled") else ActionResult(False, "Rollback is not required for the recorded state.")


class StartupFileRemediation(BaseRemediation):
    action_id = "disable_startup_file"
    requires_admin = False
    def preview(self, evidence: dict) -> dict:
        return {"action": "Move the selected Startup-folder item into CyberAudit's local backup folder.", "settings_changed": ["Selected current-user Startup item"], "requires_admin": False}
    def apply(self, evidence: dict) -> ActionResult:
        raw = evidence.get("path")
        if not raw: return ActionResult(False, "No startup file path was provided.")
        source = Path(raw).resolve(); startup = (Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup").resolve()
        if startup not in source.parents or not source.is_file(): return ActionResult(False, "Only a current-user Startup-folder file can be changed.")
        backup = Path.cwd() / "backups" / source.name
        backup.parent.mkdir(exist_ok=True); source.replace(backup)
        return ActionResult(True, "Startup item moved to local backup.", {"source": str(source), "backup": str(backup)})
    def rollback(self, backup_data: dict) -> ActionResult:
        source, backup = Path(backup_data.get("source", "")), Path(backup_data.get("backup", ""))
        if not backup.is_file(): return ActionResult(False, "Backup file is unavailable.")
        backup.replace(source); return ActionResult(True, "Startup item restored.")


class BlockInboundSmbRemediation(BaseRemediation):
    """Adds a clearly-owned inbound TCP/445 block rule; it never edits unrelated firewall policy."""
    action_id = "block_inbound_smb"
    rule_name = "CyberAudit - Block Inbound SMB"
    def preview(self, evidence: dict) -> dict:
        return {"action": "Create a CyberAudit-owned firewall rule that blocks inbound SMB (TCP 445).",
                "settings_changed": ["New inbound Windows Firewall rule for TCP 445"], "requires_admin": True,
                "warning": "This can prevent Windows file sharing and printer sharing from reaching this device."}
    def apply(self, evidence: dict) -> ActionResult:
        result = _run("if (Get-NetFirewallRule -DisplayName 'CyberAudit - Block Inbound SMB' -ErrorAction SilentlyContinue) { Write-Output 'CyberAudit rule already exists'; exit 2 }; New-NetFirewallRule -DisplayName 'CyberAudit - Block Inbound SMB' -Direction Inbound -Action Block -Protocol TCP -LocalPort 445 -Profile Any")
        if not result.success and "CyberAudit rule already exists" in result.message:
            result.message = "A CyberAudit-owned SMB block rule already exists; no duplicate was created."
        result.backup_data = {"rule_name": self.rule_name} if result.success else None
        return result
    def rollback(self, backup_data: dict) -> ActionResult:
        if backup_data.get("rule_name") != self.rule_name:
            return ActionResult(False, "Invalid rollback data.")
        return _run("Remove-NetFirewallRule -DisplayName 'CyberAudit - Block Inbound SMB'")
