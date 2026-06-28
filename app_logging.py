"""Structured application logging for DGS Sentinel AI."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


STANDARD_FIELDS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "taskName",
}

SENSITIVE_TERMS = {
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "authorization",
}


def _safe_value(
    key: str,
    value: Any,
) -> Any:
    normalized_key = key.lower()

    if any(
        term in normalized_key
        for term in SENSITIVE_TERMS
    ):
        return "[REDACTED]"

    if isinstance(value, (str, int, float, bool)):
        return value

    if value is None:
        return None

    return str(value)


class JsonFormatter(logging.Formatter):
    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(
                UTC
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key in STANDARD_FIELDS:
                continue

            payload[key] = _safe_value(
                key,
                value,
            )

        if record.exc_info:
            payload["exception"] = (
                self.formatException(
                    record.exc_info
                )
            )

        return json.dumps(
            payload,
            default=str,
        )


def configure_logging(
    log_level: str = "INFO",
) -> None:
    root_logger = logging.getLogger()

    level = getattr(
        logging,
        str(log_level).upper(),
        logging.INFO,
    )

    root_logger.setLevel(level)

    for handler in root_logger.handlers:
        if getattr(
            handler,
            "_dgs_structured_handler",
            False,
        ):
            handler.setLevel(level)
            return

    handler = logging.StreamHandler(
        sys.stdout
    )
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    handler._dgs_structured_handler = True

    root_logger.addHandler(handler)


def get_logger(
    name: str,
) -> logging.Logger:
    return logging.getLogger(name)
