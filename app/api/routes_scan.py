from threading import Thread

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.scan import Scan
from app.services.scan_service import ScanService
from app.services.scan_progress import get as get_progress

router = APIRouter(prefix="/api/scans", tags=["scans"])

@router.post("/start", status_code=201)
def start_scan(db: Session = Depends(get_db)) -> dict:
    service = ScanService()
    scan = service.create_scan(db)
    Thread(target=service.run_scan, args=(scan.id,), daemon=True).start()
    return {"id": scan.id, "status": scan.status}

@router.get("")
def list_scans(db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": s.id, "status": s.status, "started_at": s.started_at, "completed_at": s.completed_at, "posture_score": s.posture_score} for s in db.scalars(select(Scan).order_by(Scan.started_at.desc()))]

@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    return {"id": scan.id, "status": scan.status, "started_at": scan.started_at, "completed_at": scan.completed_at, "posture_score": scan.posture_score, "device_summary": scan.device_summary, "error": scan.error_message}


@router.get("/{scan_id}/progress")
def scan_progress(scan_id: str, db: Session = Depends(get_db)) -> dict:
    scan = db.get(Scan, scan_id)
    if not scan: raise HTTPException(404, "Scan not found")
    progress = get_progress(scan_id) or {"completed": 0, "total": 0, "current": scan.status.value, "detail": "No active progress information is available."}
    return {"scan_id": scan_id, "status": scan.status.value, "posture_score": scan.posture_score, "error": scan.error_message, **progress}
