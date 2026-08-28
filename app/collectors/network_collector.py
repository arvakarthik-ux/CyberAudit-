import socket

import psutil

from app.collectors.base import BaseCollector, CollectorResult


def _endpoint(addr: object) -> dict | None:
    return {"ip": addr.ip, "port": addr.port} if addr else None


class NetworkCollector(BaseCollector):
    name = "network"

    def collect(self) -> CollectorResult:
        connections = []
        try:
            for c in psutil.net_connections(kind="inet"):
                protocol = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                connections.append({"protocol": protocol, "local": _endpoint(c.laddr), "remote": _endpoint(c.raddr),
                                    "state": c.status, "pid": c.pid})
            return CollectorResult("success", {"connections": connections})
        except psutil.AccessDenied:
            return CollectorResult("permission_denied", message="Network connection metadata requires additional permission.")
