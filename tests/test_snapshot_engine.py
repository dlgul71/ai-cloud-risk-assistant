import json
from pathlib import Path

import snapshot_engine


def test_snapshot_preserves_multicloud_summary(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        snapshot_engine,
        "SNAPSHOT_DIR",
        tmp_path,
    )

    summary = {
        "security_score": 70,
        "risk_rating": "HIGH",
        "multi_cloud_security_score": 25,
        "multi_cloud_risk_score": 75,
        "multi_cloud_risk_rating": "HIGH",
        "azure_critical_findings": 2,
        "azure_high_findings": 3,
        "azure_medium_findings": 4,
        "azure_total_findings": 9,
    }

    result = snapshot_engine.save_scan_snapshot(
        summary=summary,
        assets=[],
        remediation=[],
    )

    snapshot_path = Path(result["file_path"])
    snapshot = json.loads(snapshot_path.read_text())

    assert snapshot["summary"] == summary
    assert snapshot["assets"] == []
    assert snapshot["remediation"] == []
