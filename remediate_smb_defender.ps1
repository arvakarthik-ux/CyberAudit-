# CyberAudit remediation script
# Run this script in an elevated PowerShell (Run as Administrator)

# ponytail: minimal, practical remediation helper — review before running

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error "This script must be run as Administrator. Open PowerShell 'Run as Administrator'."
        exit 1
    }
}

Assert-Admin

Write-Host "Starting CyberAudit remediation actions..." -ForegroundColor Cyan

# 1) Ensure Windows Defender service is running and set to automatic
try {
    Write-Host "Enabling and starting Microsoft Defender service (WinDefend)..." -ForegroundColor Yellow
    if (Get-Service -Name WinDefend -ErrorAction SilentlyContinue) {
        Set-Service -Name WinDefend -StartupType Automatic -ErrorAction Stop
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
        Write-Host "WinDefend set to Automatic and started (if not already)." -ForegroundColor Green
    } else {
        Write-Warning "WinDefend service not found on this system."
    }
} catch {
    Write-Warning "Failed to start/set WinDefend: $_"
}

# 2) Enable real-time protection (requires Defender cmdlets available)
try {
    Write-Host "Attempting to enable real-time protection..." -ForegroundColor Yellow
    # Some environments restrict Set-MpPreference; ignore failures but report
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Write-Host "Requested enabling real-time protection." -ForegroundColor Green
} catch {
    Write-Warning "Could not change real-time protection via Set-MpPreference: $_"
    Write-Warning "If Set-MpPreference is unavailable, ensure Microsoft Defender is installed or use your AV management tool."
}

# 3) Create firewall rule to block SMB inbound on Public profile
$ruleName = "Block SMB inbound (Public) - CyberAudit"
try {
    Write-Host "Creating firewall rule to block SMB (TCP 139,445) on Public profile..." -ForegroundColor Yellow
    # If a rule with the same name exists, leave it
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -LocalPort 139,445 -Protocol TCP -Action Block -Profile Public -Enabled True -ErrorAction Stop
        Write-Host "Firewall rule created: $ruleName" -ForegroundColor Green
    } else {
        Write-Host "Firewall rule already exists: $ruleName" -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to create firewall rule: $_"
}

# 4) (Optional) Stop & disable Server service (LanmanServer) - commented out. Enable if you do not need file/print sharing.
# Write-Host "Stopping and disabling Server service (LanmanServer)..." -ForegroundColor Yellow
# Stop-Service -Name LanmanServer -ErrorAction SilentlyContinue
# Set-Service -Name LanmanServer -StartupType Disabled
# Write-Host "LanmanServer stopped and disabled." -ForegroundColor Green

# 5) Verification output
Write-Host "\nVerification:" -ForegroundColor Cyan
try {
    Write-Host "Microsoft Defender status (AMServiceEnabled, RealTimeProtectionEnabled):" -ForegroundColor Yellow
    Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled | Format-List
} catch {
    Write-Warning "Get-MpComputerStatus failed or Defender module unavailable: $_"
}

try {
    Write-Host "Firewall rule present:" -ForegroundColor Yellow
    Get-NetFirewallRule -DisplayName $ruleName | Select-Object DisplayName,Enabled,Profile
} catch {
    Write-Warning "Could not query firewall rules: $_"
}

try {
    Write-Host "Listening TCP connections on ports 139/445 (Get-NetTCPConnection):" -ForegroundColor Yellow
    Get-NetTCPConnection -State Listen -LocalPort 139,445 | Format-Table -AutoSize
} catch {
    Write-Warning "Get-NetTCPConnection unavailable or failed: $_"
    Write-Host "Fallback: netstat -ano | findstr ":139 " or findstr ":445 "" -ForegroundColor Yellow
}

Write-Host "\nCyberAudit remediation script finished. Review the output above for any errors." -ForegroundColor Cyan
