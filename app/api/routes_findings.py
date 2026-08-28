from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.connection import ConnectionSnapshot
from app.models.finding import Finding
from app.models.process import ProcessSnapshot
from app.schemas import FindingOut
from app.services.finding_service import list_findings

router = APIRouter(prefix="/api", tags=["findings and telemetry"])

@router.get("/findings", response_model=list[FindingOut])
def findings(severity: str | None = None, category: str | None = None, q: str | None = Query(default=None), db: Session = Depends(get_db)):
    return list_findings(db, severity, category, q)

@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    value = db.get(Finding, finding_id)
    if not value: raise HTTPException(404, "Finding not found")
    return value

@router.get("/processes")
def processes(scan_id: str | None = None, db: Session = Depends(get_db)):
    statement = select(ProcessSnapshot)
    if scan_id: statement = statement.where(ProcessSnapshot.scan_id == scan_id)
    return [{"scan_id": p.scan_id, **p.data} for p in db.scalars(statement)]

@router.get("/network/connections")
def connections(scan_id: str | None = None, db: Session = Depends(get_db)):
    statement = select(ConnectionSnapshot)
    if scan_id: statement = statement.where(ConnectionSnapshot.scan_id == scan_id)
    return [{"scan_id": c.scan_id, **c.data} for c in db.scalars(statement)]
