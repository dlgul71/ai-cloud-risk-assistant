"""Real-process synthetic HTTP ingestion lifecycle test."""

import hashlib
import json
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request


def test_real_process_ingests_and_shuts_down(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    with sqlite3.connect(data_dir / "clients.db") as db:
        db.execute(
            "CREATE TABLE clients (client_key TEXT PRIMARY KEY)"
        )
        db.execute(
            "INSERT INTO clients VALUES ('synthetic-client')"
        )

    token = "synthetic-lifecycle-token-" + "x" * 40
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    uid = "d" * 64

    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps({token_hash: "synthetic-client"})
    )
    credentials.chmod(0o600)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    process = subprocess.Popen(
        [
            sys.executable,
            "-m", "linux_telemetry_start",
            "--data-dir", str(data_dir),
            "--credentials-file", str(credentials),
            "--port", str(port),
            "--serve",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 8

        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(
                    "Receiver exited: " + process.stderr.read()
                )

            try:
                with socket.create_connection(
                    ("127.0.0.1", port), timeout=0.2
                ):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("Receiver did not start")

        payload = {
            "schema_version": "1.0",
            "event_uid": uid,
            "event": {
                "event_uid": uid,
                "event_id": "synthetic:1001",
                "source": "linux_audit",
            },
        }

        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/linux/events",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Idempotency-Key": uid,
            },
            method="POST",
        )

        # Verify an invalid token cannot store an event.
        invalid_request = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/linux/events",
            data=json.dumps(payload).encode(),
            headers={
                "Authorization": "Bearer invalid-token",
                "Content-Type": "application/json",
                "Idempotency-Key": uid,
            },
            method="POST",
        )

        try:
            urllib.request.urlopen(invalid_request, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError("Invalid token was accepted")

        with sqlite3.connect(data_dir / "linux_telemetry.db") as db:
            unauthorized_count = db.execute(
                "SELECT COUNT(*) FROM linux_events WHERE event_uid = ?",
                (uid,),
            ).fetchone()[0]

        assert unauthorized_count == 0
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.loads(response.read())
            assert response.status == 200
            assert result["durable"] is True

        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=8) == 0

        with sqlite3.connect(
            data_dir / "linux_telemetry.db"
        ) as db:
            row = db.execute(
                "SELECT client_key FROM linux_events "
                "WHERE event_uid = ?",
                (uid,),
            ).fetchone()

        assert row == ("synthetic-client",)

    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=8)
        process.stderr.close()
