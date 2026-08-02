"""Persistent operational health monitoring for DGS Sentinel AI."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from storage_paths import database_path


DEFAULT_MONITORING_DB = None
SYSTEM_CLIENT_KEY = "__dgs_system__"


def _monitoring_db_path(
    db_path: Path | None = None,
) -> Path:
    if db_path is not None:
        return Path(db_path)

    if DEFAULT_MONITORING_DB is not None:
        return Path(DEFAULT_MONITORING_DB)

    return database_path(
        "operational_monitoring.db"
    )


def _normalize_client_key(
    client_key: str | None,
) -> str:
    normalized = str(client_key or "").strip()

    if not normalized:
        raise ValueError("client_key is required")

    return normalized


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
    """Create and migrate operational monitoring tables."""

    monitoring_path = _monitoring_db_path(db_path)
    monitoring_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with closing(
        sqlite3.connect(monitoring_path)
    ) as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS health_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_key TEXT NOT NULL,
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

        existing_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(health_runs)"
            )
        }

        if "client_key" not in existing_columns:
            connection.execute(
                """
                ALTER TABLE health_runs
                ADD COLUMN client_key TEXT
                """
            )

        connection.execute(
            """
            UPDATE health_runs
            SET client_key = ?
            WHERE client_key IS NULL
               OR TRIM(client_key) = ''
            """,
            (SYSTEM_CLIENT_KEY,),
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS
            health_check_results (
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
            idx_health_runs_client_checked_at
            ON health_runs(
                client_key,
                checked_at DESC
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_runs_client_status
            ON health_runs(
                client_key,
                overall_status,
                checked_at DESC
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_results_component
            ON health_check_results(
                component,
                checked_at DESC
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_health_results_run_id
            ON health_check_results(run_id)
            """
        )

        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS
            health_runs_require_client_key_insert
            BEFORE INSERT ON health_runs
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END
            """
        )

        connection.execute(
            """
            CREATE TRIGGER IF NOT EXISTS
            health_runs_require_client_key_update
            BEFORE UPDATE OF client_key
            ON health_runs
            WHEN NEW.client_key IS NULL
              OR TRIM(NEW.client_key) = ''
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'client_key is required'
                );
            END
            """
        )

        connection.commit()


def record_health_run(
    health_payload: dict[str, Any],
    *,
    client_key: str,
    db_path: Path | None = None,
    source: str = "system-health",
) -> dict[str, Any]:
    """Persist one tenant-scoped health-check execution."""

    normalized_client_key = _normalize_client_key(
        client_key
    )

    checks = health_payload.get("checks", [])

    if not isinstance(checks, list):
        raise ValueError(
            "Health payload checks must be a list."
        )

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

    monitoring_path = _monitoring_db_path(db_path)

    with closing(
        sqlite3.connect(monitoring_path)
    ) as connection:
        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO health_runs (
                client_key,
                checked_at,
                recorded_at,
                source,
                overall_status,
                pass_count,
                warning_count,
                fail_count,
                check_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                normalized_client_key,
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
        "client_key": normalized_client_key,
        "checked_at": checked_at,
        "overall_status": overall_status,
        "check_count": len(checks),
    }


def get_recent_health_runs(
    *,
    client_key: str,
    db_path: Path | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Return recent health runs for one tenant boundary."""

    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_monitoring_db(db_path)

    safe_limit = max(1, int(limit))

    with closing(
        sqlite3.connect(
            _monitoring_db_path(db_path)
        )
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
            WHERE client_key = ?
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
            """,
            (
                normalized_client_key,
                safe_limit,
            ),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


def get_component_history(
    component: str,
    *,
    client_key: str,
    db_path: Path | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    """Return component history for one tenant boundary."""

    normalized_client_key = _normalize_client_key(
        client_key
    )

    init_monitoring_db(db_path)

    safe_limit = max(1, int(limit))

    with closing(
        sqlite3.connect(
            _monitoring_db_path(db_path)
        )
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
            WHERE health_runs.client_key = ?
              AND health_check_results.component = ?
            ORDER BY
                health_check_results.checked_at DESC,
                health_check_results.id DESC
            LIMIT ?
            """,
            (
                normalized_client_key,
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
    client_key: str,
    db_path: Path | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Summarize reliability for one tenant boundary."""

    runs = get_recent_health_runs(
        client_key=client_key,
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
    """Convert a health summary into an alert decision."""

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
