from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.enums import RemediationStatus
from app.models.finding import Finding
from app.models.remediation import RemediationRecord
from app.remediation.base import BaseRemediation
from app.remediation.windows import BlockInboundSmbRemediation, DefenderRemediation, FirewallProfileRemediation, GuestAccountRemediation, StartupFileRemediation


class RemediationManager:
    actions: dict[str, BaseRemediation] = {a.action_id: a for a in [FirewallProfileRemediation(), DefenderRemediation(), GuestAccountRemediation(), StartupFileRemediation(), BlockInboundSmbRemediation()]}

    def preview(self, db: Session, finding_ids: list[str]) -> list[dict]:
        findings = list(db.scalars(select(Finding).where(Finding.id.in_(finding_ids))))
        if len(findings) != len(set(finding_ids)): raise ValueError("One or more findings do not exist.")
        previews = []
        for f in findings:
            action = self.actions.get(f.remediation_id or "")
            if not action: previews.append({"finding_id": f.id, "available": False, "reason": "No supported remediation is available."})
            else: previews.append({"finding_id": f.id, "available": True, "title": f.title, "preview": action.preview(f.evidence)})
        return previews

    def apply(self, db: Session, finding_ids: list[str], requested_by: str | None) -> list[RemediationRecord]:
        records = []
        for f in db.scalars(select(Finding).where(Finding.id.in_(finding_ids))):
            action = self.actions.get(f.remediation_id or "")
            if not action: continue
            outcome = action.apply(f.evidence)
            record = RemediationRecord(finding_id=f.id, action_id=action.action_id, requested_by=requested_by,
                status=RemediationStatus.APPLIED if outcome.success else RemediationStatus.FAILED, backup_data=outcome.backup_data, result=outcome.result, message=outcome.message)
            db.add(record); db.add(AuditLog(event_type="remediation.applied", actor=requested_by, message=outcome.message, details={"finding_id": f.id, "action": action.action_id}))
            records.append(record)
        db.commit()
        for record in records: db.refresh(record)
        return records

    def rollback(self, db: Session, record: RemediationRecord) -> RemediationRecord:
        action = self.actions.get(record.action_id)
        if not action: raise ValueError("This remediation cannot be rolled back.")
        outcome = action.rollback(record.backup_data or {})
        record.status = RemediationStatus.ROLLED_BACK if outcome.success else RemediationStatus.FAILED; record.message = outcome.message
        db.add(AuditLog(event_type="remediation.rollback", message=outcome.message, details={"record_id": record.id}))
        db.commit(); db.refresh(record); return record
