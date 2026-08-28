from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding


def list_findings(db: Session, severity: str | None = None, category: str | None = None, query: str | None = None) -> list[Finding]:
    statement = select(Finding).order_by(Finding.risk_score.desc())
    if severity: statement = statement.where(Finding.severity == severity)
    if category: statement = statement.where(Finding.category == category)
    if query: statement = statement.where(Finding.title.ilike(f"%{query}%"))
    return list(db.scalars(statement))
