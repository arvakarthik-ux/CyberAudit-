import subprocess
import re


def collect():
    """Collect listening TCP ports using netstat."""
    data = {"listening": []}
    try:
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, shell=True)
        out = res.stdout
        for line in out.splitlines():
            # example:  TCP    0.0.0.0:135      0.0.0.0:0      LISTENING       1234
            if "LISTENING" in line:
                parts = re.split(r"\s+", line.strip())
                if len(parts) >= 5:
                    proto = parts[0]
                    local = parts[1]
                    pid = parts[-1]
                    # extract port
                    if ":" in local:
                        port = local.split(":")[-1]
                    else:
                        port = local
                    data["listening"].append({"protocol": proto, "local": local, "port": port, "pid": pid})
    except Exception as e:
        data["error"] = str(e)
    return data
