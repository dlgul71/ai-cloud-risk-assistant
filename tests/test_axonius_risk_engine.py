import axonius_risk_engine


def sample_assets():
    return [
        {
            "asset_id": "asset-001",
            "hostname": "prod-server",
            "asset_type": "Server",
            "source": "AWS",
            "managed": True,
            "owner_username": "cloud-admin",
            "risk_score": 55,
        },
        {
            "asset_id": "asset-002",
            "hostname": "legacy-server",
            "asset_type": "Server",
            "source": "Active Directory",
            "managed": False,
            "owner_username": "legacy-service",
            "risk_score": 80,
        },
        {
            "asset_id": "asset-003",
            "hostname": "unknown-owner-laptop",
            "asset_type": "Endpoint",
            "source": "Endpoint Security",
            "managed": True,
            "owner_username": "missing-user",
            "risk_score": 30,
        },
    ]


def sample_identities():
    return [
        {
            "username": "cloud-admin",
            "privileged": True,
            "mfa_enabled": True,
            "orphaned": False,
            "risk_score": 45,
        },
        {
            "username": "legacy-service",
            "privileged": True,
            "mfa_enabled": False,
            "orphaned": True,
            "risk_score": 95,
        },
    ]


def sample_coverage():
    return [
        {
            "source": "AWS",
            "connected": True,
            "coverage_percent": 95,
        },
        {
            "source": "Active Directory",
            "connected": True,
            "coverage_percent": 60,
        },
        {
            "source": "Endpoint Security",
            "connected": False,
            "coverage_percent": 0,
        },
    ]


def test_correlates_asset_identity_and_coverage():
    rows = (
        axonius_risk_engine
        .generate_correlated_exposure_rows(
            sample_assets(),
            sample_identities(),
            sample_coverage(),
        )
    )

    legacy = next(
        row for row in rows
        if row["Asset ID"] == "asset-002"
    )

    assert legacy["Identity Matched"] is True
    assert legacy["Privileged"] is True
    assert legacy["MFA Enabled"] is False
    assert legacy["Orphaned Identity"] is True
    assert legacy["Coverage %"] == 60
    assert legacy["Correlated Risk Score"] == 100
    assert legacy["Priority"] == "CRITICAL"
    assert "Unmanaged asset" in legacy["Risk Drivers"]
    assert "Identity without MFA" in legacy["Risk Drivers"]
    assert "Orphaned identity" in legacy["Risk Drivers"]


def test_reports_unmatched_asset_owner():
    rows = (
        axonius_risk_engine
        .generate_correlated_exposure_rows(
            sample_assets(),
            sample_identities(),
            sample_coverage(),
        )
    )

    unmatched = next(
        row for row in rows
        if row["Asset ID"] == "asset-003"
    )

    assert unmatched["Owner"] == "missing-user"
    assert unmatched["Identity Matched"] is False
    assert unmatched["Connector Connected"] is False
    assert unmatched["Correlated Risk Score"] == 60
    assert "Asset owner not found" in unmatched["Risk Drivers"]
    assert "Disconnected source" in unmatched["Risk Drivers"]


def test_correlation_rows_are_sorted_by_risk():
    rows = (
        axonius_risk_engine
        .generate_correlated_exposure_rows(
            sample_assets(),
            sample_identities(),
            sample_coverage(),
        )
    )

    assert rows[0]["Asset ID"] == "asset-002"
    assert rows[0]["Priority"] == "CRITICAL"


def test_calculates_correlation_metrics():
    rows = (
        axonius_risk_engine
        .generate_correlated_exposure_rows(
            sample_assets(),
            sample_identities(),
            sample_coverage(),
        )
    )

    metrics = (
        axonius_risk_engine
        .calculate_correlation_metrics(rows)
    )

    assert metrics["Total Correlated Assets"] == 3
    assert metrics["Critical Correlations"] == 1
    assert metrics["High Correlations"] == 1
    assert metrics["Unmatched Asset Owners"] == 1
    assert metrics["Unmanaged Correlated Assets"] == 1
    assert (
        metrics["Assets With Disconnected Sources"]
        == 1
    )
    assert metrics["Average Correlated Risk Score"] == 75.0


def test_empty_correlation_metrics_are_safe():
    metrics = (
        axonius_risk_engine
        .calculate_correlation_metrics([])
    )

    assert metrics["Total Correlated Assets"] == 0
    assert metrics["Average Correlated Risk Score"] == 0


def test_executive_recommendations_include_correlated_exposure():
    recommendations = (
        axonius_risk_engine
        .generate_caasm_executive_recommendations(
            metrics={"CAASM Score": 80},
            identity_governance_metrics={},
            coverage_gap_metrics={},
            policy_findings=[],
            coverage_gap_findings=[],
            correlation_metrics={
                "Critical Correlations": 1,
                "High Correlations": 2,
                "Unmatched Asset Owners": 1,
                "Average Correlated Risk Score": 78.5,
            },
            correlation_rows=[
                {
                    "Hostname": "legacy-server",
                    "Priority": "CRITICAL",
                }
            ],
        )
    )

    categories = [
        item["Category"]
        for item in recommendations
    ]

    assert "Correlated Exposure" in categories
    assert "Asset Ownership" in categories
    assert "Executive Correlation Risk" in categories

    critical = next(
        item for item in recommendations
        if (
            item["Category"] == "Correlated Exposure"
            and item["Priority"] == "CRITICAL"
        )
    )

    assert "legacy-server" in critical["Recommendation"]


def test_executive_recommendations_remain_backward_compatible():
    recommendations = (
        axonius_risk_engine
        .generate_caasm_executive_recommendations(
            metrics={"CAASM Score": 90},
            identity_governance_metrics={},
            coverage_gap_metrics={},
            policy_findings=[],
            coverage_gap_findings=[],
        )
    )

    assert recommendations == [
        {
            "Priority": "STANDARD",
            "Category": "Monitoring",
            "Recommendation": (
                "Maintain recurring CAASM assessments and "
                "validate connector health regularly."
            ),
        }
    ]
