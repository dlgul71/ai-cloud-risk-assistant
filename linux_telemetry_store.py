"""Tenant-scoped Linux telemetry persistence foundation."""

import json
import re
import sqlite3
from pathlib import Path


class LinuxTelemetryStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(
            parents=True, exist_ok=True
        )

        with sqlite3.connect(self.path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS linux_events (
                    event_uid TEXT PRIMARY KEY,
                    client_key TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    received_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS
                    idx_linux_events_client
                ON linux_events(client_key)
            """)

    def ingest(self, client_key, event_uid, event):
        """Persist one event; return True if newly inserted.

        client_key must come from authenticated server-side
        authorization, never from an untrusted event payload.
        """
        if not isinstance(client_key, str) or not client_key.strip():
            raise ValueError("Authorized client key required")

        if not isinstance(event_uid, str) or not re.fullmatch(
            r"[0-9a-f]{64}", event_uid
        ):
            raise ValueError("Invalid event UID")

        if not isinstance(event, dict):
            raise ValueError("Event must be an object")

        if event.get("event_uid") != event_uid:
            raise ValueError("Event UID mismatch")

        if not isinstance(event.get("event_id"), str):
            raise ValueError("Audit event ID required")

        payload = json.dumps(
            event, sort_keys=True, allow_nan=False
        )

        if len(payload.encode("utf-8")) > 65536:
            raise ValueError("Event exceeds size limit")

        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("PRAGMA synchronous=FULL")

            cursor = db.execute("""
                INSERT OR IGNORE INTO linux_events (
                    event_uid, client_key, event_json
                ) VALUES (?, ?, ?)
            """, (event_uid, client_key.strip(), payload))

            if cursor.rowcount == 1:
                return True

            existing = db.execute("""
                SELECT client_key, event_json
                FROM linux_events
                WHERE event_uid = ?
            """, (event_uid,)).fetchone()

            if existing != (client_key.strip(), payload):
                raise ValueError(
                    "Event UID conflicts with an existing record"
                )

            return False

    def get_for_client(self, client_key):
        """Return events only for an authorized client key."""
        if not isinstance(client_key, str) or not client_key.strip():
            raise ValueError("Authorized client key required")

        with sqlite3.connect(self.path) as db:
            rows = db.execute("""
                SELECT event_json
                FROM linux_events
                WHERE client_key = ?
                ORDER BY received_at, rowid
            """, (client_key.strip(),)).fetchall()

        return [json.loads(row[0]) for row in rows]
