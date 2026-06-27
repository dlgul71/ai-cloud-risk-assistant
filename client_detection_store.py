import json
from datetime import datetime, UTC
from pathlib import Path


STORE_DIR = Path("client_scan_results")


def _safe_account_id(account_id):
    return "".join(
        character
        for character in str(account_id)
        if character.isalnum() or character in {"-", "_"}
    )


def save_client_scan_summary(account_id, summary):
    STORE_DIR.mkdir(exist_ok=True)

    payload = {
        "account_id": str(account_id),
        "saved_at": str(datetime.now(UTC)),
        **summary,
    }

    file_path = (
        STORE_DIR
        / f"client_scan_{_safe_account_id(account_id)}.json"
    )

    with open(file_path, "w") as file:
        json.dump(payload, file, indent=2, default=str)

    return file_path


def load_client_scan_summary(account_id):
    file_path = (
        STORE_DIR
        / f"client_scan_{_safe_account_id(account_id)}.json"
    )

    if not file_path.exists():
        return {}

    try:
        with open(file_path, "r") as file:
            return json.load(file)

    except Exception:
        return {}
