import sqlite3
from contextlib import closing
from types import SimpleNamespace

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


def test_configuration_fails_when_live_remediation_lacks_hmac_key(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            safe_summary=lambda: {
                "app_env": "production",
                "aws_region": "us-east-1",
                "openai_configured": True,
                "app_credentials_configured": True,
                "live_remediation_enabled": True,
                "remediation_evidence_hmac_configured": False,
                "remediation_evidence_previous_key_count": 0,
            },
        ),
    )

    results = health_checks.check_configuration()

    signing_result = next(
        result
        for result in results
        if result["Component"] == "Remediation evidence signing"
    )

    assert signing_result["Status"] == "FAIL"
    assert "HMAC signing key is missing" in signing_result["Detail"]


def test_configuration_passes_with_hmac_key_and_reports_previous_keys(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            safe_summary=lambda: {
                "app_env": "production",
                "aws_region": "us-east-1",
                "openai_configured": True,
                "app_credentials_configured": True,
                "live_remediation_enabled": True,
                "remediation_evidence_hmac_configured": True,
                "remediation_evidence_previous_key_count": 2,
            },
        ),
    )

    results = health_checks.check_configuration()

    signing_result = next(
        result
        for result in results
        if result["Component"] == "Remediation evidence signing"
    )
    previous_keys_result = next(
        result
        for result in results
        if result["Component"] == "Previous remediation evidence keys"
    )

    assert signing_result["Status"] == "PASS"
    assert previous_keys_result["Status"] == "PASS"
    assert previous_keys_result["Detail"] == "2 previous key(s) configured"


def test_configuration_reports_splunk_hec_configured(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            safe_summary=lambda: {
                "app_env": "production",
                "aws_region": "us-east-1",
                "openai_configured": True,
                "app_credentials_configured": True,
                "live_remediation_enabled": False,
                "remediation_evidence_hmac_configured": True,
                "remediation_evidence_previous_key_count": 0,
                "splunk_hec_configured": True,
            },
        ),
    )

    results = health_checks.check_configuration()

    splunk_result = next(
        result
        for result in results
        if result["Component"] == "Splunk HEC configuration"
    )

    assert splunk_result["Status"] == "PASS"
    assert splunk_result["Detail"] == (
        "HEC URL and token configured"
    )


def test_splunk_hec_health_check_passes(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            splunk_hec_url="https://splunk.example.com:8088",
            splunk_hec_token="test-token",
        ),
    )

    captured = {}

    def fake_sender(event, **kwargs):
        captured["event"] = event
        captured["kwargs"] = kwargs

        return {
            "status": "SENT",
            "splunk_text": "Success",
        }

    results = health_checks.check_splunk_hec(
        sender=fake_sender
    )

    assert results[0]["Status"] == "PASS"
    assert "accepted" in results[0]["Detail"]
    assert captured["event"]["event_type"] == (
        "dgs_sentinel_health_check"
    )
    assert captured["kwargs"]["fields"] == {
        "event_category": "platform_health",
        "component": "splunk_hec",
    }


def test_splunk_hec_health_check_warns_when_unconfigured(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            splunk_hec_url=None,
            splunk_hec_token=None,
        ),
    )

    results = health_checks.check_splunk_hec()

    assert results == [
        {
            "Component": "Splunk HEC connectivity",
            "Status": "WARN",
            "Detail": "Splunk HEC is not configured",
        }
    ]


def test_splunk_hec_health_check_reports_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "settings",
        SimpleNamespace(
            splunk_hec_url="https://splunk.example.com:8088",
            splunk_hec_token="test-token",
        ),
    )

    def failing_sender(event, **kwargs):
        raise health_checks.SplunkHECError(
            "Splunk HEC request failed."
        )

    results = health_checks.check_splunk_hec(
        sender=failing_sender
    )

    assert results[0]["Status"] == "FAIL"
    assert results[0]["Detail"] == (
        "Splunk HEC request failed."
    )


def test_health_summary_includes_optional_splunk_check(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "check_configuration",
        lambda: [],
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
    monkeypatch.setattr(
        health_checks,
        "check_splunk_hec",
        lambda: [
            {
                "Component": "Splunk HEC connectivity",
                "Status": "PASS",
                "Detail": "Connected",
            }
        ],
    )

    results = health_checks.run_health_checks(
        include_aws=False,
        include_splunk=True,
    )

    assert results["overall_status"] == "PASS"
    assert results["pass_count"] == 1
    assert results["checks"][0]["Component"] == (
        "Splunk HEC connectivity"
    )


def test_axonius_health_check_passes():
    results = health_checks.check_axonius_connectivity(
        connector_test=lambda: {
            "status": "CONNECTED",
            "mode": "Live",
            "asset_count": 3,
            "message": "Axonius API connection succeeded.",
        }
    )

    assert results == [
        {
            "Component": "Axonius connectivity",
            "Status": "PASS",
            "Detail": (
                "Axonius API connection succeeded; "
                "3 asset(s) returned"
            ),
        }
    ]


def test_axonius_health_check_warns_when_unconfigured():
    results = health_checks.check_axonius_connectivity(
        connector_test=lambda: {
            "status": "NOT_CONFIGURED",
            "mode": "Mock",
            "asset_count": 0,
            "message": "Axonius is not configured.",
        }
    )

    assert results == [
        {
            "Component": "Axonius connectivity",
            "Status": "WARN",
            "Detail": "Axonius is not configured",
        }
    ]


def test_axonius_health_check_reports_failure():
    def failing_connector():
        raise health_checks.AxoniusConnectorError(
            "Axonius request failed."
        )

    results = health_checks.check_axonius_connectivity(
        connector_test=failing_connector
    )

    assert results == [
        {
            "Component": "Axonius connectivity",
            "Status": "FAIL",
            "Detail": "Axonius request failed.",
        }
    ]


def test_health_summary_includes_optional_axonius_check(
    monkeypatch,
):
    monkeypatch.setattr(
        health_checks,
        "check_configuration",
        lambda: [],
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
    monkeypatch.setattr(
        health_checks,
        "check_axonius_connectivity",
        lambda: [
            {
                "Component": "Axonius connectivity",
                "Status": "PASS",
                "Detail": "Connected",
            }
        ],
    )

    results = health_checks.run_health_checks(
        include_aws=False,
        include_splunk=False,
        include_axonius=True,
    )

    assert results["overall_status"] == "PASS"
    assert results["pass_count"] == 1
    assert results["checks"][0]["Component"] == (
        "Axonius connectivity"
    )


def test_default_database_files_use_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        health_checks,
        "DATABASE_FILES",
        None,
    )

    database_files = (
        health_checks.get_database_files()
    )

    assert database_files == [
        tmp_path / "assets.db",
        tmp_path / "clients.db",
        tmp_path / "remediation.db",
        tmp_path / "operational_monitoring.db",
    ]


def test_default_storage_directories_use_data_directory(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv(
        "DGS_DATA_DIR",
        str(tmp_path),
    )

    monkeypatch.setattr(
        health_checks,
        "STORAGE_DIRECTORIES",
        None,
    )

    storage_directories = (
        health_checks.get_storage_directories()
    )

    assert storage_directories == [
        tmp_path,
        tmp_path / "scan_snapshots",
        tmp_path / "client_scan_results",
        tmp_path / "backups",
    ]
