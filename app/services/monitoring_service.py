from dataclasses import dataclass
import asyncio
import logging

from app.database.database import SessionLocal
from app.services.scan_service import ScanService


@dataclass
class MonitoringState:
    enabled: bool = False
    interval_seconds: int = 300


state = MonitoringState()
logger = logging.getLogger(__name__)


def configure(enabled: bool, interval_seconds: int) -> MonitoringState:
    """Stores monitoring preference. A scheduler can call ScanService periodically in a deployed worker."""
    state.enabled, state.interval_seconds = enabled, interval_seconds
    return state


async def monitoring_loop() -> None:
    """In-process opt-in periodic scan; stops with the server and creates no system persistence."""
    while True:
        await asyncio.sleep(30 if state.enabled else 60)
        if not state.enabled:
            continue
        try:
            db = SessionLocal()
            try:
                await asyncio.to_thread(ScanService().start_scan, db)
            finally:
                db.close()
            await asyncio.sleep(max(0, state.interval_seconds - 30))
        except Exception:
            logger.exception("Periodic monitoring scan failed")
