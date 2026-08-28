import json
import subprocess


def collect():
    """Collect basic Microsoft Defender status via Get-MpComputerStatus."""
    data = {}
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AMServiceRunning,AntispywareEnabled,RealTimeProtectionEnabled,ProductStatus | ConvertTo-Json -Compress"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, shell=False)
        out = res.stdout.strip()
        if out:
            data = json.loads(out)
        else:
            data = {"error": "no output from Get-MpComputerStatus"}
    except Exception as e:
        data = {"error": str(e)}
    return data
