import json
import logging

from app_logging import JsonFormatter


def test_json_formatter_redacts_sensitive_fields():
    record = logging.LogRecord(
        name="dgs_sentinel.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Security event processed",
        args=(),
        exc_info=None,
    )

    record.event = "unit_test"
    record.api_key = "secret-api-key"
    record.password = "secret-password"
    record.account_id = "123456789012"

    payload = json.loads(
        JsonFormatter().format(record)
    )

    assert payload["api_key"] == "[REDACTED]"
    assert payload["password"] == "[REDACTED]"
    assert payload["account_id"] == "123456789012"
    assert (
        payload["message"]
        == "Security event processed"
    )
