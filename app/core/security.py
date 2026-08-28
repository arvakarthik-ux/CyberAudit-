import os


def ensure_local_development() -> bool:
    """Reserved hook for deployment policy; CyberAudit intentionally has no remote-control interface."""
    return os.environ.get("CYBERAUDIT_ENVIRONMENT", "development") in {"development", "production"}
