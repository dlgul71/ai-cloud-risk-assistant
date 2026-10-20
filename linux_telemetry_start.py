"""Controlled startup for the local development receiver."""

import argparse
import signal
from pathlib import Path

from linux_telemetry_credentials import load_credential_hashes
from linux_telemetry_preflight import validate_receiver_configuration
from linux_telemetry_receiver import LinuxTelemetryReceiver
from linux_telemetry_service import create_local_server
from linux_telemetry_store import LinuxTelemetryStore


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--credentials-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--serve", action="store_true")

    args = parser.parse_args(argv)

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")

    credentials = validate_receiver_configuration(
        args.data_dir,
        args.credentials_file,
    )

    if args.check:
        print("PASS: Receiver configuration valid; no listener started")
        return 0

    store = LinuxTelemetryStore(
        args.data_dir / "linux_telemetry.db"
    )

    receiver = LinuxTelemetryReceiver(
        store=store,
        clients_db_path=args.data_dir / "clients.db",
        credential_hashes=credentials,
        credential_loader=lambda: load_credential_hashes(args.credentials_file),
    )

    server = create_local_server(receiver, port=args.port)

    def stop_on_sigterm(_signum, _frame):
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, stop_on_sigterm)

    try:
        print("Development receiver listening on 127.0.0.1", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
