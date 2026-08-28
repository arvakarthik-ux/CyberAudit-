from fastapi import APIRouter

from app.schemas import MonitorConfig
from app.services.monitoring_service import configure, state

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

@router.get("/status")
def status() -> dict:
    return {"enabled": state.enabled, "interval_seconds": state.interval_seconds,
            "note": "The server runs an opt-in periodic scan while it is running; it creates no OS persistence."}

@router.put("/config")
def config(request: MonitorConfig) -> dict:
    value = configure(request.enabled, request.interval_seconds)
    return {"enabled": value.enabled, "interval_seconds": value.interval_seconds}
