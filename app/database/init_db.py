from app.database.database import Base, engine
# Importing models registers every table before create_all runs.
from app.models import audit_log, connection, finding, process, remediation, scan  # noqa: F401


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
