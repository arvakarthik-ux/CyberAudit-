# CyberAudit

Windows-first security posture assessment, evidence-backed risk detection, and explicitly administrator-approved remediation. CyberAudit does not guarantee complete protection and never treats a heuristic process indicator as malware confirmation.

## Architecture

`collectors → analyzers → persisted findings/posture → API/dashboard/reports → admin preview → explicit confirmation → remediation/audit trail`

- `app/collectors`: defensive, read-only system, update, network, process, startup, service, account, firewall, Defender, and feature inspection. Each returns success, unsupported, permission-denied, or error state.
- `app/analyzers`: explainable rules; the transparent weighted risk engine starts at 100 and deducts severity-weighted risk. Critical findings remain individually visible.
- `app/models` and `app/database`: SQLite/SQLAlchemy persistence for scans, findings, process and connection snapshots, remediation history, and audit logs.
- `app/remediation`: bounded actions only—enable a named Firewall profile, enable Defender real-time monitoring, disable Guest, move a current-user Startup-folder file to a local backup, or create a clearly-owned inbound SMB firewall block rule. No process killing, software uninstalling, file deletion, arbitrary network blocking, or privilege escalation.
- `app/api`: documented REST routes, including explicit preview/confirmation/rollback workflows.
- `app/reports`: a detailed HTML report and portable PDF companion report.
- `app/platform`: abstract boundary for future Linux, macOS, and Android adapters. Those platforms are not implemented.

## API

- `POST /api/scans/start`, `GET /api/scans`, `GET /api/scans/{scan_id}`
- `GET /api/findings`, `GET /api/findings/{finding_id}`
- `GET /api/processes`, `GET /api/network/connections`
- `POST /api/remediation/preview`, `POST /api/remediation/apply`, `POST /api/remediation/rollback`
- `GET /api/reports/{scan_id}/html`, `GET /api/reports/{scan_id}/pdf`
- `GET /api/dashboard/summary`, `GET /api/monitoring/status`, `PUT /api/monitoring/config`

## Setup on Windows

```powershell
cd C:\path\to\CyberAudit
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python run.py
```

Open `http://127.0.0.1:8000/` for the dashboard and `http://127.0.0.1:8000/docs` for API documentation. Use the dashboard’s **Start scan** button or `POST /api/scans/start`. Once complete, the browser redirects to a local per-scan link, `http://127.0.0.1:8000/scan/<scan-id>`, which lists all completed checks, positive/no-finding controls, evidence, processes, observed connections, reports, and supported administrator controls. Scanning is designed to run as a normal user where possible; remediation will clearly fail without elevation rather than attempting elevation itself.

## Tests

```powershell
pytest -q
```

## Operational notes

- Run the server locally and use an administrator shell only when you deliberately approve an administrative remediation.
- Defender and BitLocker capabilities vary by Windows edition and endpoint-security configuration. Unsupported controls are reported as such rather than fabricated.
- The monitoring endpoint enables an in-process periodic scan for the current server lifetime. It deliberately creates no hidden process or Windows persistence mechanism; use a controlled service/worker for production deployment.
