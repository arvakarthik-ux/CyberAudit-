from sqlalchemy import ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class ConnectionSnapshot(Base):
    __tablename__ = "connection_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    pid: Mapped[int | None] = mapped_column(nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
