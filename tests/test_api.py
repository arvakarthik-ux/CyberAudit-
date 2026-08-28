from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_empty_state() -> None:
    with TestClient(app) as client:
        response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    assert response.json()["latest_scan_id"] is None


def test_remediation_requires_confirmation() -> None:
    with TestClient(app) as client:
        response = client.post("/api/remediation/apply", json={"finding_ids": ["missing"], "confirmation": False})
    assert response.status_code == 400
