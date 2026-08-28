from abc import ABC, abstractmethod


class BasePlatform(ABC):
    """Contract for future Windows, Linux, macOS, and Android adapters."""
    @property
    @abstractmethod
    def supported(self) -> bool: ...
    @abstractmethod
    def collector_names(self) -> list[str]: ...
