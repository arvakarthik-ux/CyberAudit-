from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CollectorResult:
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    message: str | None = None


class BaseCollector(ABC):
    name: str

    @abstractmethod
    def collect(self) -> CollectorResult:
        """Collect data without changing host state."""
