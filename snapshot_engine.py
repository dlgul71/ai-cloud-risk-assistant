import json
from datetime import datetime
from pathlib import Path


SNAPSHOT_DIR = Path("scan_snapshots")


def cleanup_old_snapshots(retain_count=50):
    SNAPSHOT_DIR.mkdir(exist_ok=True)

    snapshots = sorted(
        SNAPSHOT_DIR.glob("scan_snapshot_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )

    old_snapshots = snapshots[retain_count:]

    for snapshot in old_snapshots:
        snapshot.unlink()

    return len(old_snapshots)


def save_scan_snapshot(summary, assets=None, remediation=None, retain_count=50):
    SNAPSHOT_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    snapshot = {
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "assets": assets or [],
        "remediation": remediation or []
    }

    file_path = SNAPSHOT_DIR / f"scan_snapshot_{timestamp}.json"

    with open(file_path, "w") as f:
        json.dump(snapshot, f, indent=2, default=str)

    deleted_count = cleanup_old_snapshots(retain_count=retain_count)

    return {
        "file_path": str(file_path),
        "deleted_old_snapshots": deleted_count
    }
