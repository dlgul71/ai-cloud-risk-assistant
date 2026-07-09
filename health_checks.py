"""Production-readiness health checks for DGS Sentinel AI."""

from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config

from app_config import settings
from app_logging import get_logger


logger = get_logger("dgs_sentinel.health")

DATABASE_FILES = [
    Path("assets.db"),
    Path("clients.db"),
    Path("remediation.db"),
]

STORAGE_DIRECTORIES = [
    Path("."),
    Path("scan_snapshots"),
    Path("client_scan_results"),
]

REQUIRED_MODULES = [
    "streamlit",
    "pandas",
    "plotly",
    "boto3",
    "openai",
    "reportlab",
    "requests",
]


def _result(
    component: str,
    status: str,
    detail: str,
) -> dict[str, str]:
    return {
        "Component": component,
        "Status": status,
        "Detail": detail,
    }


def check_configuration() -> list[dict[str, str]]:
    summary = settings.safe_summary()
    results = []

    results.append(
        _result(
            "Application environment",
            "PASS",
            str(summary["app_env"]),
        )
    )

    results.append(
        _result(
            "AWS region",
            "PASS",
            str(summary["aws_region"]),
        )
    )

    results.append(
        _result(
            "OpenAI configuration",
            (
                "PASS"
                if summary["openai_configured"]
                else "WARN"
            ),
            (
                "Configured"
                if summary["openai_configured"]
                else "Not configured"
            ),
        )
    )

    credentials_configured = bool(
        summary["app_credentials_configured"]
    )

    results.append(
        _result(
            "Application authentication",
            (
                "PASS"
                if credentials_configured
                else "FAIL"
            ),
            (
                "Credentials configured"
                if credentials_configured
                else "Username or password missing"
            ),
        )
    )

    evidence_hmac_configured = bool(
        summary["remediation_evidence_hmac_configured"]
    )
    live_remediation_enabled = bool(
        summary["live_remediation_enabled"]
    )

    if evidence_hmac_configured:
        evidence_hmac_status = "PASS"
        evidence_hmac_detail = "Current HMAC signing key configured"
    elif live_remediation_enabled:
        evidence_hmac_status = "FAIL"
        evidence_hmac_detail = (
            "Live remediation is enabled, but the evidence "
            "HMAC signing key is missing"
        )
    else:
        evidence_hmac_status = "WARN"
        evidence_hmac_detail = (
            "Evidence HMAC signing key is not configured"
        )

    results.append(
        _result(
            "Remediation evidence signing",
            evidence_hmac_status,
            evidence_hmac_detail,
        )
    )

    results.append(
        _result(
            "Previous remediation evidence keys",
            "PASS",
            (
                f"{summary['remediation_evidence_previous_key_count']} "
                "previous key(s) configured"
            ),
        )
    )

    return results


def check_required_modules() -> list[dict[str, str]]:
    results = []

    for module_name in REQUIRED_MODULES:
        available = (
            importlib.util.find_spec(module_name)
            is not None
        )

        results.append(
            _result(
                f"Python module: {module_name}",
                "PASS" if available else "FAIL",
                (
                    "Available"
                    if available
                    else "Missing"
                ),
            )
        )

    return results


def check_databases() -> list[dict[str, str]]:
    results = []

    for database_path in DATABASE_FILES:
        if not database_path.exists():
            results.append(
                _result(
                    f"Database: {database_path.name}",
                    "WARN",
                    "Database file does not exist yet",
                )
            )
            continue

        try:
            connection = sqlite3.connect(
                (
                    f"file:{database_path.resolve()}"
                    "?mode=ro"
                ),
                uri=True,
                timeout=3,
            )

            quick_check = connection.execute(
                "PRAGMA quick_check"
            ).fetchone()

            connection.close()

            database_ok = bool(
                quick_check
                and quick_check[0] == "ok"
            )

            results.append(
                _result(
                    f"Database: {database_path.name}",
                    (
                        "PASS"
                        if database_ok
                        else "FAIL"
                    ),
                    (
                        "SQLite integrity check passed"
                        if database_ok
                        else "SQLite integrity check failed"
                    ),
                )
            )

        except Exception as error:
            logger.exception(
                "Database health check failed",
                extra={
                    "event": "database_health_failure",
                    "database": database_path.name,
                },
            )

            results.append(
                _result(
                    f"Database: {database_path.name}",
                    "FAIL",
                    type(error).__name__,
                )
            )

    return results


def check_storage() -> list[dict[str, str]]:
    results = []

    for directory in STORAGE_DIRECTORIES:
        try:
            directory.mkdir(
                parents=True,
                exist_ok=True,
            )

            with tempfile.NamedTemporaryFile(
                mode="w",
                prefix=".dgs_health_",
                dir=directory,
                delete=True,
            ) as temporary_file:
                temporary_file.write(
                    "DGS Sentinel AI health check"
                )
                temporary_file.flush()

            results.append(
                _result(
                    f"Writable storage: {directory}",
                    "PASS",
                    "Write and cleanup test passed",
                )
            )

        except Exception as error:
            logger.exception(
                "Storage health check failed",
                extra={
                    "event": "storage_health_failure",
                    "directory": str(directory),
                },
            )

            results.append(
                _result(
                    f"Writable storage: {directory}",
                    "FAIL",
                    type(error).__name__,
                )
            )

    return results


def check_aws_identity() -> list[dict[str, str]]:
    try:
        client = boto3.client(
            "sts",
            region_name=settings.aws_region,
            config=Config(
                connect_timeout=3,
                read_timeout=3,
                retries={
                    "max_attempts": 1,
                    "mode": "standard",
                },
            ),
        )

        identity = client.get_caller_identity()

        account_id = str(
            identity.get("Account", "Unknown")
        )

        return [
            _result(
                "AWS identity",
                "PASS",
                f"STS identity available for account {account_id}",
            )
        ]

    except Exception as error:
        logger.warning(
            "AWS identity health check unavailable",
            extra={
                "event": "aws_identity_health_warning",
                "error_type": type(error).__name__,
            },
        )

        return [
            _result(
                "AWS identity",
                "WARN",
                (
                    "AWS identity unavailable: "
                    f"{type(error).__name__}"
                ),
            )
        ]


def run_health_checks(
    include_aws: bool = False,
) -> dict[str, Any]:
    checks = []

    checks.extend(check_configuration())
    checks.extend(check_required_modules())
    checks.extend(check_databases())
    checks.extend(check_storage())

    if include_aws:
        checks.extend(check_aws_identity())

    fail_count = sum(
        item["Status"] == "FAIL"
        for item in checks
    )

    warning_count = sum(
        item["Status"] == "WARN"
        for item in checks
    )

    pass_count = sum(
        item["Status"] == "PASS"
        for item in checks
    )

    if fail_count:
        overall_status = "FAIL"
    elif warning_count:
        overall_status = "WARN"
    else:
        overall_status = "PASS"

    payload = {
        "checked_at": datetime.now(
            UTC
        ).isoformat(),
        "overall_status": overall_status,
        "pass_count": pass_count,
        "warning_count": warning_count,
        "fail_count": fail_count,
        "checks": checks,
    }

    logger.info(
        "Health checks completed",
        extra={
            "event": "health_check_completed",
            "overall_status": overall_status,
            "pass_count": pass_count,
            "warning_count": warning_count,
            "fail_count": fail_count,
            "aws_check_included": include_aws,
        },
    )

    return payload
