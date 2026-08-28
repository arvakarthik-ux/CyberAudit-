from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.finding import Finding
from app.models.remediation import RemediationRecord
from app.models.scan import Scan
from app.reports.html_generator import render_report
from app.reports.pdf_generator import generate_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])

def data(scan_id: str, db: Session):
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())))
    remediations = list(db.scalars(select(RemediationRecord).join(Finding).where(Finding.scan_id == scan_id)))
    return scan, findings, remediations

@router.get("/{scan_id}/html", response_class=Response)
def html(scan_id: str, db: Session = Depends(get_db)):
    return Response(render_report(*data(scan_id, db)), media_type="text/html")

@router.get("/{scan_id}/pdf")
def pdf(scan_id: str, db: Session = Depends(get_db)):
    return Response(generate_pdf(*data(scan_id, db)), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cyberaudit-{scan_id}.pdf"'})
