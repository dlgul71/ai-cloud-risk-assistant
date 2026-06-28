import sqlite3
from contextlib import closing

import health_checks


def test_database_integrity_check_passes(
    monkeypatch,
    tmp_path,
):
    database_path = tmp_path / "test.db"

    with closing(
        sqlite3.connect(database_path)
    ) as connection:
        connection.execute(
            "CREATE TABLE health_test "
            "(id INTEGER PRIMARY KEY)"
        )
        connection.commit()

    monkeypatch.setattr(
        health_checks,
        "DATABASE_FILES",
        [database_path],
    )

    results = health_checks.check_databases()

    assert len(results) == 1
    assert results[0]["Status"] == "PASS"


def test_storage_write_check_passes(
    monkeypatch,
    tmp_path,
):
    first_directory = tmp_path / "snapshots"
    second_directory = tmp_path / "results"

    monkeypatch.setattr(
        health_checks,
        "STORAGE_DIRECTORIES",
        [
            first_directory,
            second_directory,
        ],
    )

    results = health_checks.check_storage()

    assert len(results) == 2
    assert all(
        result["Status"] == "PASS"
        for result in results
    )


def test_health_summary_reports_pass(
    monkeypatch,
):
    pass_result = [
        {
            "Component": "Test",
            "Status": "PASS",
            "Detail": "Passed",
        }
    ]

    monkeypatch.setattr(
        health_checks,
        "check_configuration",
        lambda: pass_result,
    )
    monkeypatch.setattr(
        health_checks,
        "check_required_modules",
        lambda: pass_result,
    )
    monkeypatch.setattr(
        health_checks,
        "check_databases",
        lambda: pass_result,
    )
    monkeypatch.setattr(
        health_checks,
        "check_storage",
        lambda: pass_result,
    )

    results = health_checks.run_health_checks(
        include_aws=False
    )

    assert results["overall_status"] == "PASS"
    assert results["pass_count"] == 4
    assert results["warning_count"] == 0
    assert results["fail_count"] == 0


def test_health_summary_reports_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "check_configuration",
        lambda: [
            {
                "Component": "Configuration",
                "Status": "FAIL",
                "Detail": "Missing",
            }
        ],
    )
    monkeypatch.setattr(
        health_checks,
        "check_required_modules",
        lambda: [],
    )
    monkeypatch.setattr(
        health_checks,
        "check_databases",
        lambda: [],
    )
    monkeypatch.setattr(
        health_checks,
        "check_storage",
        lambda: [],
    )

    results = health_checks.run_health_checks(
        include_aws=False
    )

    assert results["overall_status"] == "FAIL"
    assert results["fail_count"] == 1
