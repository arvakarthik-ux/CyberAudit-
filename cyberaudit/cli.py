import argparse
import json
import sys
from datetime import datetime
import uuid
from cyberaudit.collectors import system as system_collector
from cyberaudit.collectors import network as network_collector
from cyberaudit.collectors import firewall as firewall_collector
from cyberaudit.collectors import defender as defender_collector
from cyberaudit.analyzers import security_checks, risk_engine
from cyberaudit.output import terminal, json_report
from cyberaudit.utils.vm_detector import is_virtual_machine, get_vm_info


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cyberaudit", description="CyberAudit CLI - Windows security scanner")
    sub = parser.add_subparsers(dest="cmd")

    scan_p = sub.add_parser("scan", help="Run a security scan")
    scan_p.add_argument("--json", dest="jsonfile", help="Write JSON report to file")
    scan_p.add_argument("--host-only", action="store_true", help="Abort if running inside a VM (ensure scanning the physical host)")

    sub.add_parser("version", help="Print version")

    rem_p = sub.add_parser("remediate", help="Write remediation PowerShell script to disk (does not execute)")
    rem_p.add_argument("--path", default="remediate_smb_defender.ps1", help="Path to write the remediation script")

    agg_p = sub.add_parser("aggregate", help="Aggregate multiple JSON reports")
    agg_p.add_argument("reports", nargs="+", help="Paths to report JSON files or directories containing JSON reports")
    agg_p.add_argument("--avg", action="store_true", help="Show average, min and max scores")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        run_scan(args.jsonfile, host_only=getattr(args, "host_only", False))
    elif args.cmd == "version":
        from cyberaudit import __version__
        print(__version__)
    elif args.cmd == "remediate":
        write_remediation_script(args.path)
    elif args.cmd == "aggregate":
        aggregate_reports(args.reports, show_avg=args.avg)
    else:
        parser.print_help()


def run_scan(jsonfile=None, host_only: bool = False):
    print("Starting CyberAudit scan...")

    # If host_only requested, abort when running inside a virtual machine
    if host_only:
        try:
            info = None
            try:
                from cyberaudit.utils.vm_detector import get_vm_info
                info = get_vm_info()
            except Exception:
                info = None

            is_vm = False
            try:
                is_vm = is_virtual_machine()
            except Exception:
                # detection failure; treat as unknown
                is_vm = None

            if info:
                manu = info.get("Manufacturer") or ""
                model = info.get("Model") or ""
                print(f"VM detection: Manufacturer='{manu}', Model='{model}'")

            if is_vm is True:
                print("Aborting: this environment appears to be a virtual machine. --host-only was specified to ensure host-only scanning.")
                return
            elif is_vm is None:
                print("VM detection failed; aborting because --host-only was specified.")
                return
            # else is_vm is False -> continue
        except Exception:
            # If unexpected error, be conservative and abort
            print("VM detection encountered an error; aborting because --host-only was specified.")
            return

    system = system_collector.collect()
    network = network_collector.collect()
    firewall = firewall_collector.collect()
    defender = defender_collector.collect()

    facts = {"system": system, "network": network, "firewall": firewall, "defender": defender}

    findings = security_checks.run_checks(facts)
    score = risk_engine.calculate_score(findings)

    # Probe Manufacturer/Model for diagnostics and include in report
    try:
        vm_info = get_vm_info()
    except Exception:
        vm_info = None

    result = {
        "system": system,
        "score": score,
        "findings": [f.to_dict() for f in findings],
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hardware_probe": vm_info
    }

    terminal.print_result(result)

    if jsonfile:
        json_report.write_json(result, jsonfile)
        print(f"Wrote JSON report to {jsonfile}")


def write_remediation_script(path: str = "remediate_smb_defender.ps1"):
    """Write the built-in remediation script to disk. Does not execute it."""
    import os

    here = os.path.abspath(os.path.dirname(__file__))
    # path relative to project root if not absolute
    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)

    # Try to find an existing remediation script in the project (created by the assistant)
    candidate = os.path.join(os.getcwd(), "remediate_smb_defender.ps1")
    if os.path.exists(candidate):
        print(f"Remediation script already exists at: {candidate}")
        print("To run it, open an elevated PowerShell and execute: ")
        print(f"  PowerShell -ExecutionPolicy Bypass -File \"{candidate}\"")
        return

    # Fallback content: conservative remediation actions
    content = r'''# CyberAudit remediation script
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
'''

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Wrote remediation script to: {path}")
        print("To run it, open an elevated PowerShell and execute:")
        print(f"  PowerShell -ExecutionPolicy Bypass -File \"{path}\"")
    except Exception as e:
        print(f"Failed to write remediation script: {e}")


def aggregate_reports(paths, show_avg: bool = False):
    """Aggregate multiple JSON report files or directories and print per-host scores and counts."""
    import os
    import glob

    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(glob.glob(os.path.join(p, "*.json")))
        else:
            files.append(p)

    results = []
    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"Failed to read {fpath}: {e}")
            continue
        sysinfo = data.get("system", {})
        name = sysinfo.get("hostname") or sysinfo.get("node") or os.path.basename(fpath)
        score = data.get("score")
        findings = data.get("findings", [])
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for fi in findings:
            sev = (fi.get("severity") or "").upper()
            if sev in counts:
                counts[sev] += 1
        results.append({"path": fpath, "name": name, "score": score, "counts": counts, "total": len(findings)})

    if not results:
        print("No valid reports found to aggregate.")
        return

    print("\nAggregated report scores:")
    header = "{:<30} {:>6} {:>8} {:>6} {:>6} {:>6} {:>8}".format("Host","Score","Critical","High","Medium","Low","Total")
    print(header)
    print("-" * len(header))
    scores = []
    for r in results:
        scores.append(r.get("score") if isinstance(r.get("score"), (int, float)) else None)
        print("{:<30} {:>6} {:>8} {:>6} {:>6} {:>6} {:>8}".format(
            r.get("name"),
            str(r.get("score")),
            r["counts"]["CRITICAL"],
            r["counts"]["HIGH"],
            r["counts"]["MEDIUM"],
            r["counts"]["LOW"],
            r.get("total")
        ))

    numeric_scores = [s for s in scores if isinstance(s, (int, float))]
    if show_avg and numeric_scores:
        avg = sum(numeric_scores) / len(numeric_scores)
        print(f"\nAverage score: {avg:.1f}")
        print(f"Min score: {min(numeric_scores)}, Max score: {max(numeric_scores)}")


if __name__ == "__main__":
    main()
