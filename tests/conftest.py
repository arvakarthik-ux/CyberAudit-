import os
from pathlib import Path

os.environ["CYBERAUDIT_DATABASE_URL"] = "sqlite:///./test_cyberaudit.db"


def pytest_sessionfinish(session, exitstatus):  # type: ignore[no-untyped-def]
    Path("test_cyberaudit.db").unlink(missing_ok=True)
