import json
from pathlib import Path

import caasm_snapshot_engine


def configure_snapshot_directory(
    monkeypatch,
    tmp_path,
):
    snapshot_dir = tmp_path / "caasm_snapshots"

    monkeypatch.setattr(
        caasm_snapshot_engine,
        "CAASM_SNAPSHOT_DIR",
        snapshot_dir,
    )

    return snapshot_dir


def test_snapshot_persists_correlation_results(
    monkeypatch,
    tmp_path,
):
    snapshot_dir = configure_snapshot_directory(
        monkeypatch,
        tmp_path,
    )

    file_path = caasm_snapshot_engine.save_caasm_snapshot(
        connector_mode="Mock",
        metrics={"CAASM Score": 55},
        identity_governance_metrics={
            "Orphaned Accounts": 1
        },
        coverage_gap_metrics={
            "Critical Coverage Gaps": 2
        },
        correlation_metrics={
            "Critical Correlations": 1,
            "Average Correlated Risk Score": 75.0,
        },
        correlation_rows=[
            {
                "Asset ID": "asset-001",
                "Correlated Risk Score": 90,
                "Priority": "CRITICAL",
            }
        ],
    )

    saved_path = Path(file_path)

    assert saved_path.parent == snapshot_dir
    assert saved_path.exists()

    payload = json.loads(saved_path.read_text())

    assert payload["connector_mode"] == "Mock"
    assert payload["correlation_metrics"] == {
        "Critical Correlations": 1,
        "Average Correlated Risk Score": 75.0,
    }
    assert payload["correlation_rows"][0]["Asset ID"] == (
        "asset-001"
    )


def test_snapshot_correlation_defaults_are_safe(
    monkeypatch,
    tmp_path,
):
    configure_snapshot_directory(
        monkeypatch,
        tmp_path,
    )

    file_path = caasm_snapshot_engine.save_caasm_snapshot(
        connector_mode="Mock",
        metrics={},
        identity_governance_metrics={},
        coverage_gap_metrics={},
    )

    payload = json.loads(
        Path(file_path).read_text()
    )

    assert payload["correlation_metrics"] == {}
    assert payload["correlation_rows"] == []


def test_load_snapshots_returns_correlation_data(
    monkeypatch,
    tmp_path,
):
    configure_snapshot_directory(
        monkeypatch,
        tmp_path,
    )

    caasm_snapshot_engine.save_caasm_snapshot(
        connector_mode="Live",
        metrics={"CAASM Score": 80},
        identity_governance_metrics={},
        coverage_gap_metrics={},
        correlation_metrics={
            "High Correlations": 2
        },
        correlation_rows=[
            {"Asset ID": "asset-002"}
        ],
    )

    snapshots = (
        caasm_snapshot_engine
        .load_caasm_snapshots()
    )

    assert len(snapshots) == 1
    assert snapshots[0]["correlation_metrics"][
        "High Correlations"
    ] == 2
    assert snapshots[0]["correlation_rows"] == [
        {"Asset ID": "asset-002"}
    ]
    assert snapshots[0]["snapshot_file"].startswith(
        "caasm_snapshot_"
    )
