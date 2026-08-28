import json
import subprocess


def collect():
    """Try to get firewall profiles via PowerShell Get-NetFirewallProfile. Returns dict or error."""
    data = {}
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = res.stdout.strip()
        if out:
            # Could be an array or single object
            data = json.loads(out)
        else:
            data = {"error": "no output from Get-NetFirewallProfile"}
    except Exception as e:
        data = {"error": str(e)}
    return data
