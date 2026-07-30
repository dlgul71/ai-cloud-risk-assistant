"""Persistent operational health monitoring for DGS Sentinel AI."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from storage_paths import database_path


DEFAULT_MONITORING_DB = None


def _monitoring_db_path(
    db_path: Path | None = None,
) -> Path:
    return (
        Path(db_path)
        if db_path is not None
        else database_path(
            "operational_monitoring.db"
        )
    )


def _normalize_timestamp(
    value: datetime | str | None = None,
) -> str:
    """Return a UTC ISO-8601 timestamp."""

    if value is None:
        timestamp = datetime.now(UTC)
    elif isinstance(value, datetime):
        timestamp = value
    else:
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    return timestamp.astimezone(UTC).isoformat()


def init_monitoring_db(
    db_path: Path | None = None,
) -> None:
    """Create health-run and component-result tables."""

    database_path = _monitoring_db_path(db_path)
    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with closing(
        sqlite3.connect(database_path)
    ) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS health_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checked_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                source TEXT NOT NULL,
                overall_status TEXT NOT NULL,
                pass_count INTEGER NOT NULL DEFAULT 0,
                warning_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                check_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS health_check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                component TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                FOREIGN KEY (run_id)
                    REFERENCES health_runs(id)
                    ON DELETE CASCADE
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_runs_checked_at
            ON health_runs(checked_at DESC)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_runs_status
            ON health_runs(overall_status, checked_at DESC)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_results_component
            ON health_check_results(component, checked_at DESC)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_results_run_id
            ON health_check_results(run_id)
            """
        )

        connection.commit()


def record_health_run(
    health_payload: dict[str, Any],
    *,
    db_path: Path | None = None,
    source: str = "system-health",
) -> dict[str, Any]:
    """Persist one health-check execution and its component results."""

    init_monitoring_db(db_path)

    checked_at = _normalize_timestamp(
        health_payload.get("checked_at")
    )
    recorded_at = _normalize_timestamp()

    overall_status = str(
        health_payload.get(
            "overall_status",
            "UNKNOWN",
        )
    ).upper()

    checks = health_payload.get("checks", [])

    if not isinstance(checks, list):
        raise ValueError(
            "Health payload checks must be a list."
        )

    database_path = _monitoring_db_path(db_path)

    with closing(
        sqlite3.connect(database_path)
    ) as connection:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO health_runs (
                checked_at,
                recorded_at,
                source,
                overall_status,
                pass_count,
                warning_count,
                fail_count,
                check_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                checked_at,
                recorded_at,
                str(source),
                overall_status,
                int(
                    health_payload.get(
                        "pass_count",
                        0,
                    )
                    or 0
                ),
                int(
                    health_payload.get(
                        "warning_count",
                        0,
                    )
                    or 0
                ),
                int(
                    health_payload.get(
                        "fail_count",
                        0,
                    )
                    or 0
                ),
                len(checks),
            ),
        )

        run_id = int(cursor.lastrowid)

        for check in checks:
            if not isinstance(check, dict):
                raise ValueError(
                    "Each health check must be a dictionary."
                )

            component = str(
                check.get(
                    "Component",
                    check.get(
                        "component",
                        "Unknown component",
                    ),
                )
            )
            status = str(
                check.get(
                    "Status",
                    check.get(
                        "status",
                        "UNKNOWN",
                    ),
                )
            ).upper()
            detail = str(
                check.get(
                    "Detail",
                    check.get(
                        "detail",
                        "",
                    ),
                )
            )

            cursor.execute(
                """
                INSERT INTO health_check_results (
                    run_id,
                    checked_at,
                    component,
                    status,
                    detail
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    checked_at,
                    component,
                    status,
                    detail,
                ),
            )

        connection.commit()

    return {
        "status": "RECORDED",
        "run_id": run_id,
        "checked_at": checked_at,
        "overall_status": overall_status,
        "check_count": len(checks),
    }


def get_recent_health_runs(
    *,
    db_path: Path | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Return recent health executions, newest first."""

    init_monitoring_db(db_path)

    safe_limit = max(1, int(limit))

    with closing(
        sqlite3.connect(_monitoring_db_path(db_path))
    ) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                checked_at,
                recorded_at,
                source,
                overall_status,
                pass_count,
                warning_count,
                fail_count,
                check_count
            FROM health_runs
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_component_history(
    component: str,
    *,
    db_path: Path | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Return recent results for one monitored component."""

    init_monitoring_db(db_path)

    safe_limit = max(1, int(limit))

    with closing(
        sqlite3.connect(_monitoring_db_path(db_path))
    ) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                health_check_results.id,
                health_check_results.run_id,
                health_check_results.checked_at,
                health_check_results.component,
                health_check_results.status,
                health_check_results.detail,
                health_runs.source,
                health_runs.overall_status
            FROM health_check_results
            INNER JOIN health_runs
                ON health_runs.id =
                    health_check_results.run_id
            WHERE health_check_results.component = ?
            ORDER BY
                health_check_results.checked_at DESC,
                health_check_results.id DESC
            LIMIT ?
            """,
            (
                str(component),
                safe_limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def summarize_health_history(
    *,
    db_path: Path | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Summarize operational reliability across recent runs."""

    runs = get_recent_health_runs(
        db_path=db_path,
        limit=limit,
    )

    total_runs = len(runs)
    pass_runs = sum(
        run["overall_status"] == "PASS"
        for run in runs
    )
    warning_runs = sum(
        run["overall_status"] == "WARN"
        for run in runs
    )
    failed_runs = sum(
        run["overall_status"] == "FAIL"
        for run in runs
    )

    pass_rate_percent = (
        round(
            pass_runs / total_runs * 100,
            2,
        )
        if total_runs
        else 0.0
    )

    return {
        "total_runs": total_runs,
        "pass_runs": pass_runs,
        "warning_runs": warning_runs,
        "failed_runs": failed_runs,
        "pass_rate_percent": pass_rate_percent,
        "latest_status": (
            runs[0]["overall_status"]
            if runs
            else "UNKNOWN"
        ),
        "latest_checked_at": (
            runs[0]["checked_at"]
            if runs
            else None
        ),
    }


def evaluate_health_alert(
    health_payload: dict[str, Any],
) -> dict[str, Any]:
    """Convert a health summary into an operational alert decision."""

    overall_status = str(
        health_payload.get(
            "overall_status",
            "UNKNOWN",
        )
    ).upper()

    warning_count = int(
        health_payload.get(
            "warning_count",
            0,
        )
        or 0
    )
    fail_count = int(
        health_payload.get(
            "fail_count",
            0,
        )
        or 0
    )

    if overall_status == "FAIL" or fail_count:
        return {
            "level": "CRITICAL",
            "should_notify": True,
            "message": (
                "DGS Sentinel AI health check failed: "
                f"{fail_count} failed component(s)."
            ),
        }

    if overall_status == "WARN" or warning_count:
        return {
            "level": "WARNING",
            "should_notify": True,
            "message": (
                "DGS Sentinel AI health check completed with "
                f"{warning_count} warning(s)."
            ),
        }

    return {
        "level": "OK",
        "should_notify": False,
        "message": "All monitored health checks passed.",
    }
