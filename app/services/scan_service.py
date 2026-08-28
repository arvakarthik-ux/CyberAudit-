import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.analyzers.security_posture_analyzer import SecurityPostureAnalyzer
from app.collectors.defender_collector import DefenderCollector
from app.collectors.firewall_collector import FirewallCollector
from app.collectors.network_collector import NetworkCollector
from app.collectors.process_collector import ProcessCollector
from app.collectors.security_feature_collector import SecurityFeatureCollector
from app.collectors.service_collector import ServiceCollector
from app.collectors.software_collector import SoftwareCollector
from app.collectors.startup_collector import StartupCollector
from app.collectors.system_collector import SystemCollector
from app.collectors.update_collector import UpdateCollector
from app.collectors.user_collector import UserCollector
from app.database.database import SessionLocal
from app.models.audit_log import AuditLog
from app.models.connection import ConnectionSnapshot
from app.models.enums import ScanStatus
from app.models.finding import Finding
from app.models.process import ProcessSnapshot
from app.models.scan import Scan
from app.services.scan_progress import update

logger = logging.getLogger(__name__)


class ScanService:
    collectors = [SystemCollector(), UpdateCollector(), SoftwareCollector(), FirewallCollector(), DefenderCollector(), NetworkCollector(), ProcessCollector(),
                  StartupCollector(), ServiceCollector(), UserCollector(), SecurityFeatureCollector()]

    def create_scan(self, db: Session) -> Scan:
        scan = Scan(status=ScanStatus.PENDING)
        db.add(scan); db.commit(); db.refresh(scan)
        update(scan.id, 0, len(self.collectors), "Queued", "Waiting for the local scan worker.")
        return scan

    def run_scan(self, scan_id: str) -> None:
        """Runs in a local background thread; every individual collector remains read-only."""
        db = SessionLocal()
        try:
            scan = db.get(Scan, scan_id)
            if not scan:
                return
            scan.status = ScanStatus.RUNNING; db.commit()
            collected: dict = {}
            total = len(self.collectors)
            for index, collector in enumerate(self.collectors):
                update(scan_id, index, total, collector.name.replace("_", " ").title(), f"Inspecting {collector.name.replace('_', ' ')}…")
                result = collector.collect()
                collected[collector.name] = {**result.data, "_status": result.status, "_message": result.message}
                detail = self._result_summary(collector.name, result.data, result.status)
                update(scan_id, index + 1, total, collector.name.replace("_", " ").title(), detail)
            update(scan_id, total, total, "Risk analysis", "Generating explainable findings and posture score…")
            findings, score = SecurityPostureAnalyzer().analyze(collected)
            scan.device_summary = collected; scan.posture_score = score
            for item in findings:
                db.add(Finding(scan_id=scan.id, **item))
            for p in collected.get("processes", {}).get("processes", []):
                db.add(ProcessSnapshot(scan_id=scan.id, pid=p["pid"], name=p["name"], path=p.get("path"), data=p))
            for c in collected.get("network", {}).get("connections", []):
                db.add(ConnectionSnapshot(scan_id=scan.id, pid=c.get("pid"), data=c))
            scan.status = ScanStatus.COMPLETED; scan.completed_at = datetime.utcnow()
            db.add(AuditLog(event_type="scan.completed", message="Security posture scan completed.", details={"scan_id": scan.id, "score": score}))
            db.commit(); update(scan_id, total, total, "Complete", f"Scan complete. Posture score: {score}/100.")
        except Exception as exc:
            logger.exception("Scan failed")
            scan = db.get(Scan, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED; scan.error_message = str(exc)[:1000]; scan.completed_at = datetime.utcnow(); db.commit()
            update(scan_id, 0, len(self.collectors), "Failed", "The scan stopped before completion. Review server logs for details.")
        finally:
            db.close()

    @staticmethod
    def _result_summary(name: str, data: dict, status: str) -> str:
        if status != "success":
            return f"{name.replace('_', ' ').title()} check returned: {status}."
        if name == "processes": return f"Captured {len(data.get('processes', []))} running processes."
        if name == "network": return f"Captured {len(data.get('connections', []))} listening ports and network connections."
        if name == "software": return f"Enumerated {len(data.get('items', []))} installed application entries."
        return f"Completed {name.replace('_', ' ')} check."
