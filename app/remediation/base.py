from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ActionResult:
    success: bool
    message: str
    backup_data: dict[str, Any] | None = None
    result: dict[str, Any] | None = None


class BaseRemediation(ABC):
    action_id: str
    requires_admin: bool = True

    @abstractmethod
    def preview(self, evidence: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    def apply(self, evidence: dict[str, Any]) -> ActionResult: ...

    @abstractmethod
    def rollback(self, backup_data: dict[str, Any]) -> ActionResult: ...
