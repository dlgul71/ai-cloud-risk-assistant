"""Read-only validation before starting the Linux receiver."""

import sqlite3
from pathlib import Path

from linux_telemetry_credentials import load_credential_hashes


def validate_receiver_configuration(data_dir, credentials_file):
    data_dir = Path(data_dir)
    credentials_file = Path(credentials_file)

    if not data_dir.is_dir() or data_dir.is_symlink():
        raise ValueError("Invalid receiver data directory")

    clients_db = data_dir / "clients.db"

    if not clients_db.is_file() or clients_db.is_symlink():
        raise ValueError("Client database is unavailable")

    credentials = load_credential_hashes(credentials_file)

    uri = clients_db.resolve().as_uri() + "?mode=ro"

    with sqlite3.connect(uri, uri=True) as db:
        client_keys = {
            row[0]
            for row in db.execute(
                "SELECT client_key FROM clients"
            )
        }

    if not set(credentials.values()).issubset(client_keys):
        raise ValueError("Unknown credential client assignment")

    return credentials
