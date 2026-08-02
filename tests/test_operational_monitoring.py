import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

import operational_monitoring


def health_payload(
    *,
    checked_at: datetime,
    overall_status: str = "PASS",
    pass_count: int = 4,
    warning_count: int = 0,
    fail_count: int = 0,
):
    return {
        "checked_at": checked_at.isoformat(),
        "overall_status": overall_status,
        "pass_count": pass_count,
        "warning_count": warning_count,
        "fail_count": fail_count,
        "checks": [
            {
                "Component": "Database: assets.db",
                "Status": overall_status,
                "Detail": "Test result",
            }
        ],
    }


def test_schema_includes_client_key(tmp_path):
    database_path = tmp_path / "monitoring.db"

    operational_monitoring.init_monitoring_db(
        database_path
    )

    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(health_runs)"
            )
        }

    assert "client_key" in columns


def test_record_health_run_persists_summary_and_checks(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"
    checked_at = datetime(
        2026,
        7,
        29,
        2,
        30,
        tzinfo=UTC,
    )

    result = operational_monitoring.record_health_run(
        health_payload(checked_at=checked_at),
        client_key="client-a",
        db_path=database_path,
        source="unit-test",
    )

    assert result["status"] == "RECORDED"
    assert result["run_id"] == 1
    assert result["client_key"] == "client-a"
    assert result["check_count"] == 1

    runs = operational_monitoring.get_recent_health_runs(
        client_key="client-a",
        db_path=database_path,
    )

    assert len(runs) == 1
    assert runs[0]["overall_status"] == "PASS"
    assert runs[0]["source"] == "unit-test"
    assert runs[0]["check_count"] == 1


def test_recent_health_runs_are_newest_first(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"

    first_time = datetime(
        2026,
        7,
        29,
        1,
        0,
        tzinfo=UTC,
    )
    second_time = first_time + timedelta(hours=1)

    operational_monitoring.record_health_run(
        health_payload(
            checked_at=first_time,
            overall_status="WARN",
            warning_count=1,
            pass_count=3,
        ),
        client_key="client-a",
        db_path=database_path,
    )

    operational_monitoring.record_health_run(
        health_payload(
            checked_at=second_time,
            overall_status="PASS",
        ),
        client_key="client-a",
        db_path=database_path,
    )

    runs = operational_monitoring.get_recent_health_runs(
        client_key="client-a",
        db_path=database_path,
        limit=2,
    )

    assert runs[0]["overall_status"] == "PASS"
    assert runs[1]["overall_status"] == "WARN"


def test_health_runs_are_isolated_by_client_key(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"
    checked_at = datetime(
        2026,
        7,
        29,
        2,
        0,
        tzinfo=UTC,
    )

    operational_monitoring.record_health_run(
        health_payload(
            checked_at=checked_at,
            overall_status="PASS",
        ),
        client_key="client-a",
        db_path=database_path,
        source="client-a-check",
    )

    operational_monitoring.record_health_run(
        health_payload(
            checked_at=checked_at,
            overall_status="FAIL",
            pass_count=2,
            fail_count=1,
        ),
        client_key="client-b",
        db_path=database_path,
        source="client-b-check",
    )

    client_a_runs = (
        operational_monitoring
        .get_recent_health_runs(
            client_key="client-a",
            db_path=database_path,
        )
    )

    client_b_runs = (
        operational_monitoring
        .get_recent_health_runs(
            client_key="client-b",
            db_path=database_path,
        )
    )

    assert len(client_a_runs) == 1
    assert len(client_b_runs) == 1
    assert client_a_runs[0]["source"] == "client-a-check"
    assert client_b_runs[0]["source"] == "client-b-check"


def test_component_history_filters_by_client_and_component(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"
    checked_at = datetime(
        2026,
        7,
        29,
        3,
        0,
        tzinfo=UTC,
    )

    payload = health_payload(checked_at=checked_at)
    payload["checks"].append(
        {
            "Component": "AWS identity",
            "Status": "WARN",
            "Detail": "Credentials unavailable",
        }
    )

    operational_monitoring.record_health_run(
        payload,
        client_key="client-a",
        db_path=database_path,
    )

    operational_monitoring.record_health_run(
        payload,
        client_key="client-b",
        db_path=database_path,
    )

    history = operational_monitoring.get_component_history(
        "AWS identity",
        client_key="client-a",
        db_path=database_path,
    )

    assert len(history) == 1
    assert history[0]["component"] == "AWS identity"
    assert history[0]["status"] == "WARN"
    assert history[0]["detail"] == (
        "Credentials unavailable"
    )


def test_summary_uses_only_requested_client(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"
    base_time = datetime(
        2026,
        7,
        29,
        4,
        0,
        tzinfo=UTC,
    )

    client_a_statuses = (
        ("PASS", 4, 0, 0),
        ("PASS", 4, 0, 0),
        ("WARN", 3, 1, 0),
        ("FAIL", 2, 0, 1),
    )

    for index, (
        status,
        pass_count,
        warning_count,
        fail_count,
    ) in enumerate(client_a_statuses):
        operational_monitoring.record_health_run(
            health_payload(
                checked_at=(
                    base_time
                    + timedelta(minutes=index)
                ),
                overall_status=status,
                pass_count=pass_count,
                warning_count=warning_count,
                fail_count=fail_count,
            ),
            client_key="client-a",
            db_path=database_path,
        )

    operational_monitoring.record_health_run(
        health_payload(
            checked_at=base_time + timedelta(hours=1),
            overall_status="PASS",
        ),
        client_key="client-b",
        db_path=database_path,
    )

    summary = (
        operational_monitoring
        .summarize_health_history(
            client_key="client-a",
            db_path=database_path,
            limit=10,
        )
    )

    assert summary["total_runs"] == 4
    assert summary["pass_runs"] == 2
    assert summary["warning_runs"] == 1
    assert summary["failed_runs"] == 1
    assert summary["pass_rate_percent"] == 50.0
    assert summary["latest_status"] == "FAIL"


def test_existing_runs_migrate_to_system_key(
    tmp_path,
):
    database_path = tmp_path / "monitoring.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE health_runs (
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
                "2026-07-29T01:00:00+00:00",
                "2026-07-29T01:00:01+00:00",
                "legacy-system-health",
                "PASS",
                1,
                0,
                0,
                1,
            ),
        )

        connection.commit()

    operational_monitoring.init_monitoring_db(
        database_path
    )

    runs = operational_monitoring.get_recent_health_runs(
        client_key=(
            operational_monitoring.SYSTEM_CLIENT_KEY
        ),
        db_path=database_path,
    )

    assert len(runs) == 1
    assert runs[0]["source"] == "legacy-system-health"


def test_missing_client_key_is_rejected(tmp_path):
    database_path = tmp_path / "monitoring.db"
    checked_at = datetime.now(UTC)

    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        operational_monitoring.record_health_run(
            health_payload(checked_at=checked_at),
            client_key="",
            db_path=database_path,
        )

    with pytest.raises(
        ValueError,
        match="client_key is required",
    ):
        operational_monitoring.get_recent_health_runs(
            client_key="",
            db_path=database_path,
        )


def test_evaluate_health_alert_reports_critical_failure():
    alert = operational_monitoring.evaluate_health_alert(
        {
            "overall_status": "FAIL",
            "warning_count": 0,
            "fail_count": 2,
        }
    )

    assert alert["level"] == "CRITICAL"
    assert alert["should_notify"] is True
    assert "2 failed" in alert["message"]


def test_evaluate_health_alert_reports_warning():
    alert = operational_monitoring.evaluate_health_alert(
        {
            "overall_status": "WARN",
            "warning_count": 3,
            "fail_count": 0,
        }
    )

    assert alert["level"] == "WARNING"
    assert alert["should_notify"] is True
    assert "3 warning" in alert["message"]


def test_evaluate_health_alert_reports_healthy():
    alert = operational_monitoring.evaluate_health_alert(
        {
            "overall_status": "PASS",
            "warning_count": 0,
            "fail_count": 0,
        }
    )

    assert alert == {
        "level": "OK",
        "should_notify": False,
        "message": "All monitored health checks passed.",
    }


def test_default_monitoring_database_uses_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        operational_monitoring,
        "DEFAULT_MONITORING_DB",
        None,
    )

    operational_monitoring.record_health_run(
        {
            "checked_at": (
                "2026-07-29T23:30:00+00:00"
            ),
            "overall_status": "PASS",
            "pass_count": 1,
            "warning_count": 0,
            "fail_count": 0,
            "checks": [
                {
                    "Component": "Storage",
                    "Status": "PASS",
                    "Detail": "Available",
                }
            ],
        },
        client_key=(
            operational_monitoring.SYSTEM_CLIENT_KEY
        ),
    )

    assert (
        tmp_path / "operational_monitoring.db"
    ).exists()
