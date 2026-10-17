"""Tests for controlled Linux telemetry receiver startup."""

import json
import sqlite3

import pytest

import linux_telemetry_start as start


@pytest.fixture
def configuration(tmp_path):
    data = tmp_path / "data"
    data.mkdir()

    with sqlite3.connect(data / "clients.db") as db:
        db.execute(
            "CREATE TABLE clients (client_key TEXT PRIMARY KEY)"
        )
        db.execute(
            "INSERT INTO clients VALUES ('demo-client')"
        )

    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps({"a" * 64: "demo-client"})
    )
    credentials.chmod(0o600)

    return [
        "--data-dir", str(data),
        "--credentials-file", str(credentials),
    ]


def test_check_does_not_start_listener(
    configuration, monkeypatch, capsys
):
    def forbidden(*args, **kwargs):
        raise AssertionError("Listener must not start")

    monkeypatch.setattr(start, "create_local_server", forbidden)

    assert start.main(configuration + ["--check"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_serve_closes_on_keyboard_interrupt(
    configuration, monkeypatch
):
    actions = []

    class FakeServer:
        def serve_forever(self):
            actions.append("started")
            raise KeyboardInterrupt

        def server_close(self):
            actions.append("closed")

    def fake_server(receiver, *, port):
        assert port == 8765
        return FakeServer()

    monkeypatch.setattr(start, "create_local_server", fake_server)

    assert start.main(configuration + ["--serve"]) == 0
    assert actions == ["started", "closed"]


def test_unknown_client_fails_preflight(configuration, tmp_path):
    credential_path = configuration[3]
    from pathlib import Path

    Path(credential_path).write_text(
        json.dumps({"a" * 64: "unknown-client"})
    )

    with pytest.raises(ValueError):
        start.main(configuration + ["--check"])


def test_invalid_port_rejected(configuration):
    with pytest.raises(SystemExit):
        start.main(configuration + [
            "--serve", "--port", "0"
        ])


def test_sigterm_closes_server_and_restores_handler(
    configuration, monkeypatch
):
    actions = []
    previous_handler = object()

    def fake_signal(signum, handler):
        assert signum == start.signal.SIGTERM
        actions.append(("signal", handler))
        return previous_handler

    class FakeServer:
        def serve_forever(self):
            actions.append(("running", None))
            installed_handler = actions[0][1]
            installed_handler(start.signal.SIGTERM, None)

        def server_close(self):
            actions.append(("closed", None))

    monkeypatch.setattr(start.signal, "signal", fake_signal)
    monkeypatch.setattr(
        start,
        "create_local_server",
        lambda receiver, *, port: FakeServer(),
    )

    assert start.main(configuration + ["--serve"]) == 0

    assert callable(actions[0][1])
    assert actions[1] == ("running", None)
    assert actions[2] == ("signal", previous_handler)
    assert actions[3] == ("closed", None)
