from sqlalchemy import ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.database import Base


class ProcessSnapshot(Base):
    __tablename__ = "process_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    pid: Mapped[int] = mapped_column()
    name: Mapped[str] = mapped_column(String(255))
    path: Mapped[str | None] = mapped_column(String(2048))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
