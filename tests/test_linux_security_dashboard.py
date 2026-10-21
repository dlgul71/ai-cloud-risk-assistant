import tempfile
import unittest
from pathlib import Path

from linux_security_dashboard import load_linux_security_summary
from linux_telemetry_store import LinuxTelemetryStore


class LinuxSecurityDashboardTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = LinuxTelemetryStore(
            Path(self.temp.name) / "test_linux.db"
        )

        for client, letter, severity in [
            ("client-A", "a", "critical"),
            ("client-B", "b", "low"),
        ]:
            uid = letter * 64
            self.store.ingest(
                client,
                uid,
                {
                    "event_uid": uid,
                    "event_id": f"test-{letter}",
                    "severity": severity,
                    "source": "linux_audit",
                },
            )

    def tearDown(self):
        self.temp.cleanup()

    def test_authorized_client(self):
        session = {
            "authenticated_client_keys": ["client-A"],
            "authenticated_is_global_admin": False,
        }

        result = load_linux_security_summary(
            self.store, session, "client-A"
        )

        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["critical_events"], 1)
        self.assertEqual(
            result["recent_events"][0]["event_id"],
            "test-a",
        )

    def test_cross_tenant_access_denied(self):
        session = {
            "authenticated_client_keys": ["client-A"],
            "authenticated_is_global_admin": False,
        }

        with self.assertRaises(PermissionError):
            load_linux_security_summary(
                self.store, session, "client-B"
            )

    def test_global_admin(self):
        session = {
            "authenticated_is_global_admin": True,
        }

        result = load_linux_security_summary(
            self.store, session, "client-B"
        )

        self.assertEqual(result["total_events"], 1)
        self.assertEqual(result["low_events"], 1)

    def test_unassigned_user_denied(self):
        with self.assertRaises(PermissionError):
            load_linux_security_summary(
                self.store, {}, "client-A"
            )


if __name__ == "__main__":
    unittest.main()
