import platform
import socket
from datetime import datetime

import psutil

from app.collectors.base import BaseCollector, CollectorResult
from app.collectors.windows_utils import powershell_json


class SystemCollector(BaseCollector):
    name = "system"

    def collect(self) -> CollectorResult:
        disks = [{"device": p.device, "total_gb": round(psutil.disk_usage(p.mountpoint).total / 2**30, 1),
                  "free_gb": round(psutil.disk_usage(p.mountpoint).free / 2**30, 1)}
                 for p in psutil.disk_partitions(all=False) if p.fstype]
        data = {"computer_name": socket.gethostname(), "os_name": platform.platform(), "version": platform.version(),
                "build": platform.release(), "architecture": platform.machine(), "cpu": platform.processor() or "Unknown",
                "ram_gb": round(psutil.virtual_memory().total / 2**30, 1), "disks": disks,
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()}
        edition = powershell_json("Get-ComputerInfo | Select-Object WindowsProductName,WindowsDisplayVersion | ConvertTo-Json -Compress")
        if edition.status == "success" and edition.data.get("items"):
            data["windows"] = edition.data["items"][0]
        return CollectorResult("success", data)
