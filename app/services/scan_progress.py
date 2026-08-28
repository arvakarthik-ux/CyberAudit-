"""In-memory progress for active local scans; final results are persisted in SQLite."""
from threading import Lock

_lock = Lock()
_progress: dict[str, dict] = {}


def update(scan_id: str, completed: int, total: int, current: str, detail: str) -> None:
    with _lock:
        _progress[scan_id] = {"completed": completed, "total": total, "current": current, "detail": detail}


def get(scan_id: str) -> dict | None:
    with _lock:
        return _progress.get(scan_id)
