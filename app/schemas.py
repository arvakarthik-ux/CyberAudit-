from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import Severity


class FindingOut(BaseModel):
    id: str
    title: str
    category: str
    severity: Severity
    risk_score: float
    confidence: str
    status: str
    description: str
    evidence: dict[str, Any]
    impact: str
    recommendation: str
    remediation_available: bool
    requires_admin: bool
    remediation_id: str | None
    detected_at: datetime

    model_config = {"from_attributes": True}


class RemediationSelection(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=25)


class RemediationApplyRequest(RemediationSelection):
    confirmation: bool
    requested_by: str | None = Field(default=None, max_length=255)


class RollbackRequest(BaseModel):
    remediation_record_id: str
    confirmation: bool


class MonitorConfig(BaseModel):
    enabled: bool
    interval_seconds: int = Field(default=300, ge=60, le=86400)
