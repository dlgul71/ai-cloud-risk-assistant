import json
from datetime import datetime
from pathlib import Path


SNAPSHOT_DIR = Path("scan_snapshots")


def save_scan_snapshot(summary, assets=None, remediation=None):
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

    return str(file_path)
