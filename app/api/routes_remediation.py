from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.remediation import RemediationRecord
from app.remediation.manager import RemediationManager
from app.schemas import RemediationApplyRequest, RemediationSelection, RollbackRequest

router = APIRouter(prefix="/api/remediation", tags=["remediation"])

@router.get("/history")
def history(scan_id: str | None = None, db: Session = Depends(get_db)):
    from sqlalchemy import select
    from app.models.finding import Finding
    query = select(RemediationRecord).order_by(RemediationRecord.created_at.desc())
    if scan_id:
        query = query.join(Finding).where(Finding.scan_id == scan_id)
    return [{"id": r.id, "finding_id": r.finding_id, "action_id": r.action_id, "status": r.status, "message": r.message, "created_at": r.created_at, "can_rollback": bool(r.backup_data)} for r in db.scalars(query)]

@router.post("/preview")
def preview(request: RemediationSelection, db: Session = Depends(get_db)):
    try: return RemediationManager().preview(db, request.finding_ids)
    except ValueError as exc: raise HTTPException(400, str(exc))

@router.post("/apply")
def apply(request: RemediationApplyRequest, db: Session = Depends(get_db)):
    if not request.confirmation: raise HTTPException(400, "Explicit confirmation is required; no changes were made.")
    records = RemediationManager().apply(db, request.finding_ids, request.requested_by)
    return [{"id": r.id, "finding_id": r.finding_id, "status": r.status, "message": r.message} for r in records]

@router.post("/rollback")
def rollback(request: RollbackRequest, db: Session = Depends(get_db)):
    if not request.confirmation: raise HTTPException(400, "Explicit confirmation is required; no changes were made.")
    record = db.get(RemediationRecord, request.remediation_record_id)
    if not record: raise HTTPException(404, "Remediation record not found")
    try: value = RemediationManager().rollback(db, record)
    except ValueError as exc: raise HTTPException(400, str(exc))
    return {"id": value.id, "status": value.status, "message": value.message}
