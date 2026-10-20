"""Local HTTP adapter for DGS Linux telemetry ingestion.

Development-only transport. Do not expose directly to the internet.
"""

import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler
from linux_telemetry_receiver import CredentialConfigurationUnavailable

MAX_REQUEST_BYTES = 128 * 1024
EVENT_PATH = "/v1/linux/events"


class LinuxTelemetryHTTPHandler(BaseHTTPRequestHandler):
    receiver = None

    def log_message(self, format, *args):
        # Avoid logging security-event payloads or credentials.
        pass

    def respond(self, status, body):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self.wfile.write(encoded)

    def do_POST(self):
        self.close_connection = True

        if self.path != EVENT_PATH:
            return self.respond(404, {"error": "Not found"})

        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return self.respond(401, {"error": "Unauthorized"})

        token = authorization[len("Bearer "):]

        if not token or len(token) > 4096:
            return self.respond(401, {"error": "Unauthorized"})

        if self.headers.get("Transfer-Encoding"):
            return self.respond(400, {"error": "Invalid request"})

        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            return self.respond(400, {"error": "Invalid length"})

        length = int(lengths[0])

        if length < 1 or length > MAX_REQUEST_BYTES:
            return self.respond(413, {"error": "Invalid size"})

        if self.headers.get("Content-Type") != "application/json":
            return self.respond(415, {"error": "Unsupported media type"})

        try:
            self.connection.settimeout(5)
            raw = self.rfile.read(length)

            if len(raw) != length:
                raise ValueError("Incomplete request")

            payload = json.loads(raw)

            if not isinstance(payload, dict):
                raise ValueError("Invalid payload")

            uid = payload.get("event_uid")
            idempotency_key = self.headers.get("Idempotency-Key")

            if (
                not isinstance(uid, str)
                or not re.fullmatch(r"[0-9a-f]{64}", uid)
                or uid != idempotency_key
            ):
                raise ValueError("Invalid event identity")

            result = self.receiver.accept_event(token, payload)

        except CredentialConfigurationUnavailable:
            return self.respond(503, {"error": "Service unavailable"})
        except PermissionError:
            return self.respond(401, {"error": "Unauthorized"})
        except (ValueError, TypeError, UnicodeError):
            return self.respond(400, {"error": "Invalid event"})
        except (sqlite3.Error, OSError):
            return self.respond(
                503, {"error": "Storage unavailable"}
            )

        self.respond(200, result)


def make_handler(receiver):
    """Bind a receiver to the HTTP handler."""
    return type(
        "BoundTelemetryHandler",
        (LinuxTelemetryHTTPHandler,),
        {"receiver": receiver},
    )
