import psutil

from app.collectors.base import BaseCollector, CollectorResult


class ProcessCollector(BaseCollector):
    name = "processes"

    def collect(self) -> CollectorResult:
        processes = []
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "memory_info"]):
            try:
                info = p.info
                processes.append({"pid": info["pid"], "ppid": info["ppid"], "name": info["name"] or "Unknown", "path": info["exe"],
                                  "command_line": " ".join(info["cmdline"] or []), "username": info["username"],
                                  "created": info["create_time"], "memory_mb": round((info["memory_info"].rss if info["memory_info"] else 0) / 2**20, 1)})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return CollectorResult("success", {"processes": processes})
