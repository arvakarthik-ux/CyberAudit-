from abc import ABC, abstractmethod
from typing import Any


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, collected: dict[str, Any]) -> list[dict[str, Any]]:
        """Return normalized, explainable finding dictionaries."""
