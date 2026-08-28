from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_findings import router as findings_router
from app.api.routes_monitoring import router as monitoring_router
from app.api.routes_remediation import router as remediation_router
from app.api.routes_reports import router as reports_router
from app.api.routes_scan import router as scan_router
from app.api.routes_ui import router as ui_router
from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.database.init_db import init_db
from app.services.monitoring_service import monitoring_loop


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    init_db()
    task = asyncio.create_task(monitoring_loop())
    try:
        yield
    finally:
        task.cancel()


settings = get_settings()
app = FastAPI(
    title=settings.app_name,
    description="Windows security posture assessment with administrator-approved remediation.",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(dashboard_router)
app.include_router(scan_router)
app.include_router(findings_router)
app.include_router(monitoring_router)
app.include_router(remediation_router)
app.include_router(reports_router)
app.include_router(ui_router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


@app.get("/", include_in_schema=False)
def home():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/api/dashboard/")
