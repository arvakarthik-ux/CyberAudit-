from app.analyzers.risk_engine import posture_label, posture_score, severity_for


def test_severity_boundaries() -> None:
    assert severity_for(80).value == "HIGH"
    assert severity_for(15).value == "LOW"


def test_posture_is_capped_and_explained() -> None:
    score = posture_score([{"severity": "HIGH", "risk_score": 100}, {"severity": "MEDIUM", "risk_score": 100}])
    assert score == 70
    assert posture_label(score) == "Needs Attention"
