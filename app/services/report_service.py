from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.models.remediation import RemediationRecord
from app.models.scan import Scan


def scan_report_data(db: Session, scan_id: str) -> tuple[Scan | None, list[Finding], list[RemediationRecord]]:
    scan = db.get(Scan, scan_id)
    if not scan: return None, [], []
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id)))
    remediations = list(db.scalars(select(RemediationRecord).join(Finding).where(Finding.scan_id == scan_id)))
    return scan, findings, remediations
