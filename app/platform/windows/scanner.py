import platform

from app.platform.base_platform import BasePlatform


class WindowsPlatform(BasePlatform):
    @property
    def supported(self) -> bool:
        return platform.system() == "Windows"
    def collector_names(self) -> list[str]:
        return ["system", "updates", "software", "firewall", "defender", "network", "processes", "startup", "services", "users", "security_features"]
