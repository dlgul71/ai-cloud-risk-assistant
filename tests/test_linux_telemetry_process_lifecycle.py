"""Real subprocess lifecycle test for the local receiver."""

import hashlib
import json
import signal
import socket
import sqlite3
import subprocess
import sys
import time


def test_real_process_stops_on_sigterm(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    with sqlite3.connect(data_dir / "clients.db") as db:
        db.execute(
            "CREATE TABLE clients (client_key TEXT PRIMARY KEY)"
        )
        db.execute(
            "INSERT INTO clients VALUES ('synthetic-client')"
        )

    token_hash = hashlib.sha256(
        b"synthetic-process-test-token"
    ).hexdigest()

    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps({token_hash: "synthetic-client"})
    )
    credentials.chmod(0o600)

    # Reserve an available local development port.
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    command = [
        sys.executable,
        "-m", "linux_telemetry_start",
        "--data-dir", str(data_dir),
        "--credentials-file", str(credentials),
        "--port", str(port),
        "--serve",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        deadline = time.monotonic() + 8

        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(
                    "Receiver exited before becoming ready: "
                    + process.stderr.read()
                )

            try:
                with socket.create_connection(
                    ("127.0.0.1", port), timeout=0.2
                ):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("Receiver did not become ready")

        process.send_signal(signal.SIGTERM)

        assert process.wait(timeout=8) == 0

        with socket.socket() as probe:
            probe.settimeout(1)
            assert probe.connect_ex(
                ("127.0.0.1", port)
            ) != 0

    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=8)
        process.stderr.close()
