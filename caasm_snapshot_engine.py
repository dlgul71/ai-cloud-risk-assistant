import json
from datetime import datetime, UTC
from pathlib import Path


CAASM_SNAPSHOT_DIR = Path("caasm_snapshots")


def save_caasm_snapshot(
    connector_mode,
    metrics,
    identity_governance_metrics,
    coverage_gap_metrics,
    policy_findings=None,
    coverage_gap_findings=None,
    retain_count=50
):
    CAASM_SNAPSHOT_DIR.mkdir(exist_ok=True)

    now = datetime.now(UTC)

    snapshot = {
        "scan_time": now.isoformat(),
        "connector_mode": connector_mode,
        "metrics": metrics,
        "identity_governance_metrics": identity_governance_metrics,
        "coverage_gap_metrics": coverage_gap_metrics,
        "policy_findings": policy_findings or [],
        "coverage_gap_findings": coverage_gap_findings or []
    }

    file_path = CAASM_SNAPSHOT_DIR / (
        f"caasm_snapshot_{now.strftime('%Y%m%d_%H%M%S')}.json"
    )

    with open(file_path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    cleanup_old_caasm_snapshots(retain_count=retain_count)

    return str(file_path)


def cleanup_old_caasm_snapshots(retain_count=50):
    CAASM_SNAPSHOT_DIR.mkdir(exist_ok=True)

    snapshots = sorted(
        CAASM_SNAPSHOT_DIR.glob("caasm_snapshot_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    for snapshot in snapshots[retain_count:]:
        snapshot.unlink()


def load_caasm_snapshots():
    CAASM_SNAPSHOT_DIR.mkdir(exist_ok=True)

    snapshots = []

    for file_path in sorted(
        CAASM_SNAPSHOT_DIR.glob("caasm_snapshot_*.json")
    ):
        try:
            with open(file_path, "r") as f:
                snapshot = json.load(f)

            snapshot["snapshot_file"] = file_path.name
            snapshots.append(snapshot)

        except Exception:
            continue

    return snapshots
