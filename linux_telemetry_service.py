"""Loopback-only Linux telemetry development service."""

from http.server import ThreadingHTTPServer

from linux_telemetry_http import make_handler


def create_local_server(receiver, *, host="127.0.0.1", port=8765):
    if host != "127.0.0.1":
        raise ValueError("Receiver must bind to IPv4 loopback")

    if (
        type(port) is not int
        or not 0 <= port <= 65535
    ):
        raise ValueError("Invalid receiver port")

    server = ThreadingHTTPServer(
        ("127.0.0.1", port),
        make_handler(receiver),
    )
    server.daemon_threads = False

    return server
