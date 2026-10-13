"""Authenticated Linux telemetry receiver service logic."""

import hashlib
import hmac
import sqlite3
from pathlib import Path

from linux_telemetry_store import LinuxTelemetryStore


class LinuxTelemetryReceiver:
    def __init__(
        self,
        *,
        store: LinuxTelemetryStore,
        clients_db_path,
        credential_hashes,
    ):
        self.store = store
        self.clients_db_path = Path(clients_db_path)
        self.credential_hashes = dict(credential_hashes)

    def _authenticate(self, token):
        if not isinstance(token, str) or len(token) < 32:
            raise PermissionError("Unauthorized collector")

        supplied_hash = hashlib.sha256(
            token.encode("utf-8")
        ).hexdigest()

        client_key = None

        for expected_hash, assigned_key in (
            self.credential_hashes.items()
        ):
            if hmac.compare_digest(
                supplied_hash, expected_hash
            ):
                client_key = assigned_key

        if not client_key:
            raise PermissionError("Unauthorized collector")

        return client_key

    def _client_exists(self, client_key):
        if not self.clients_db_path.is_file():
            return False

        uri = (
            self.clients_db_path.resolve().as_uri()
            + "?mode=ro"
        )

        with sqlite3.connect(uri, uri=True) as db:
            row = db.execute(
                """
                SELECT 1 FROM clients
                WHERE client_key = ?
                LIMIT 1
                """,
                (client_key,),
            ).fetchone()

        return row is not None

    def accept_event(self, token, payload):
        """Confirm only after authorized durable persistence."""

        client_key = self._authenticate(token)

        if not self._client_exists(client_key):
            raise PermissionError("Unauthorized collector")

        if not isinstance(payload, dict):
            raise ValueError("Invalid event envelope")

        if payload.get("schema_version") != "1.0":
            raise ValueError("Unsupported schema version")

        event_uid = payload.get("event_uid")
        event = payload.get("event")

        self.store.ingest(
            client_key,
            event_uid,
            event,
        )

        return {
            "accepted": True,
            "durable": True,
            "event_uid": event_uid,
        }
