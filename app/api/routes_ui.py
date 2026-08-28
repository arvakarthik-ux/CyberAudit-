from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import PROJECT_ROOT
from app.database.database import get_db
from app.models.finding import Finding
from app.models.remediation import RemediationRecord
from app.models.scan import Scan

router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "app" / "templates"))

@router.get("/findings", response_class=HTMLResponse, include_in_schema=False)
def findings_page(request: Request, db: Session = Depends(get_db)):
    findings = list(db.scalars(select(Finding).order_by(Finding.risk_score.desc())))
    return templates.TemplateResponse(request, "findings.html", {"findings": findings})

@router.get("/remediation", response_class=HTMLResponse, include_in_schema=False)
def remediation_page(request: Request):
    return templates.TemplateResponse(request, "remediation.html", {})


@router.get("/history", response_class=HTMLResponse, include_in_schema=False)
def history_page(request: Request, db: Session = Depends(get_db)):
    scans = list(db.scalars(select(Scan).order_by(Scan.started_at.desc())))
    return templates.TemplateResponse(request, "history.html", {"scans": scans})


@router.get("/scan/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
def scan_results_page(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())))
    records = list(db.scalars(select(RemediationRecord).join(Finding).where(Finding.scan_id == scan_id).order_by(RemediationRecord.created_at.desc())))
    return templates.TemplateResponse(request, "scan_results.html", {"scan": scan, "findings": findings, "records": records, "captured": scan.device_summary or {}})
