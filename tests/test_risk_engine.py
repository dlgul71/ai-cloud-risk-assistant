from risk_engine import (
    calculate_asset_risk,
    calculate_unified_risk,
)


def test_calculate_asset_risk_for_public_running_ec2():
    asset = {
        "public_ip": "203.0.113.10",
        "state": "running",
        "asset_type": "EC2",
    }

    assert calculate_asset_risk(asset) == 50


def test_unified_risk_preserves_existing_aws_calculation():
    result = calculate_unified_risk(
        base_risk=10,
        securityhub_count=2,
        guardduty_count=1,
    )

    assert result == 80


def test_unified_risk_accepts_zero_azure_findings():
    result = calculate_unified_risk(
        base_risk=10,
        securityhub_count=2,
        guardduty_count=1,
        azure_critical_count=0,
        azure_high_count=0,
        azure_medium_count=0,
    )

    assert result == 80


def test_azure_findings_contribute_to_unified_risk():
    result = calculate_unified_risk(
        base_risk=10,
        securityhub_count=0,
        guardduty_count=0,
        azure_critical_count=1,
        azure_high_count=2,
        azure_medium_count=3,
    )

    assert result == 65


def test_unified_risk_is_capped_at_100():
    result = calculate_unified_risk(
        base_risk=70,
        securityhub_count=2,
        guardduty_count=1,
        azure_critical_count=2,
        azure_high_count=3,
        azure_medium_count=4,
    )

    assert result == 100


def test_negative_counts_do_not_reduce_risk():
    result = calculate_unified_risk(
        base_risk=20,
        securityhub_count=-1,
        guardduty_count=-1,
        azure_critical_count=-1,
        azure_high_count=-1,
        azure_medium_count=-1,
    )

    assert result == 20


def test_numeric_string_counts_are_supported():
    result = calculate_unified_risk(
        base_risk="10",
        securityhub_count="1",
        guardduty_count="1",
        azure_critical_count="1",
        azure_high_count="1",
        azure_medium_count="1",
    )

    assert result == 95


from risk_engine import summarize_azure_findings


def test_summarizes_network_and_storage_azure_findings():
    result = summarize_azure_findings(
        network_exposure={
            "summary": {
                "critical_findings": 4,
                "high_findings": 2,
                "medium_findings": 1,
                "total_findings": 7,
            }
        },
        storage_exposure={
            "summary": {
                "critical": 0,
                "high": 2,
                "medium": 2,
                "findings": 4,
            }
        },
    )

    assert result == {
        "critical": 4,
        "high": 4,
        "medium": 3,
        "total": 11,
    }


def test_summarizes_missing_azure_results_as_zero():
    result = summarize_azure_findings(
        network_exposure=None,
        storage_exposure=None,
    )

    assert result == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "total": 0,
    }


def test_summarizes_numeric_strings_and_ignores_negative_values():
    result = summarize_azure_findings(
        network_exposure={
            "summary": {
                "critical_findings": "2",
                "high_findings": "-1",
                "medium_findings": "3",
                "total_findings": "5",
            }
        },
        storage_exposure={
            "summary": {
                "critical": "1",
                "high": "2",
                "medium": "-4",
                "findings": "3",
            }
        },
    )

    assert result == {
        "critical": 3,
        "high": 2,
        "medium": 3,
        "total": 8,
    }
