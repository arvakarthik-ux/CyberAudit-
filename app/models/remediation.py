from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base
from app.models.enums import RemediationStatus


class RemediationRecord(Base):
    __tablename__ = "remediation_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False, index=True)
    action_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[RemediationStatus] = mapped_column(Enum(RemediationStatus), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    backup_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
