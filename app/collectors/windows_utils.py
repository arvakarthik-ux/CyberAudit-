import json
import platform
import subprocess
from typing import Any

from app.collectors.base import CollectorResult


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def powershell_json(script: str, timeout: int = 20) -> CollectorResult:
    """Run a fixed PowerShell command. User input is never interpolated here."""
    if not is_windows():
        return CollectorResult("unsupported", message="This collector is supported on Windows only.")
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError:
        return CollectorResult("unsupported", message="PowerShell is unavailable.")
    except subprocess.TimeoutExpired:
        return CollectorResult("error", message="PowerShell command timed out.")
    if completed.returncode != 0:
        return CollectorResult("error", message=(completed.stderr or "PowerShell command failed.").strip()[:500])
    raw = completed.stdout.strip()
    if not raw:
        return CollectorResult("success", {})
    try:
        parsed: Any = json.loads(raw)
        return CollectorResult("success", {"items": parsed if isinstance(parsed, list) else [parsed]})
    except json.JSONDecodeError:
        return CollectorResult("error", message="PowerShell returned invalid JSON.")
