from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates

from app.database.database import get_db
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.enums import Severity
from app.core.config import PROJECT_ROOT

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "app" / "templates"))


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)) -> dict:
    """Return the persisted posture summary; scanners populate it in Phase 2+."""
    latest_scan = db.scalar(select(Scan).order_by(Scan.started_at.desc()).limit(1))
    counts = {severity.value: 0 for severity in Severity}
    if latest_scan:
        rows = db.execute(
            select(Finding.severity, func.count(Finding.id)).where(Finding.scan_id == latest_scan.id).group_by(Finding.severity)
        )
        counts.update({severity.value: count for severity, count in rows})
    return {
        "latest_scan_id": latest_scan.id if latest_scan else None,
        "posture_score": latest_scan.posture_score if latest_scan else None,
        "severity_counts": counts,
        "message": "No scans have been executed yet." if not latest_scan else "Summary loaded.",
    }


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard(request: Request, db: Session = Depends(get_db)):
    summary = dashboard_summary(db)
    latest = db.get(Scan, summary["latest_scan_id"]) if summary["latest_scan_id"] else None
    findings = list(db.scalars(select(Finding).where(Finding.scan_id == latest.id).order_by(Finding.risk_score.desc()).limit(8))) if latest else []
    return templates.TemplateResponse(request, "dashboard.html", {"summary": summary, "latest": latest, "findings": findings})
