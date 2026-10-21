"""Network binding safeguards for the local receiver."""

import pytest

from linux_telemetry_service import create_local_server


@pytest.mark.parametrize("host", [
    "0.0.0.0",
    "::",
    "192.168.1.10",
])
def test_non_loopback_bind_rejected(host):
    with pytest.raises(ValueError):
        create_local_server(None, host=host, port=0)


def test_invalid_port_rejected():
    with pytest.raises(ValueError):
        create_local_server(None, port=-1)


def test_local_bind_succeeds():
    server = create_local_server(None, port=0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()
