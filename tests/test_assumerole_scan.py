from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

import scan_engine_phase3_assumerole as engine


ROLE = "arn:aws:iam::123456789012:role/TestScan"
ACCOUNT = "123456789012"


def denied(operation):
    return ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
        operation,
    )


@pytest.fixture(autouse=True)
def isolated_scan(monkeypatch):
    """Replace AWS and persistence boundaries for every test."""
    monkeypatch.setattr(engine, "REGIONS", ["us-east-1", "us-west-2"])
    replacements = {
        "client_boto3_client": Mock(
            side_effect=AssertionError("Unexpected AWS client request")
        ),
        "test_client_identity": Mock(
            return_value={"status": "SUCCESS", "account": ACCOUNT}
        ),
        "scan_client_ec2": Mock(return_value=[]),
        "scan_client_iam": Mock(return_value=([], [])),
        "scan_client_s3": Mock(return_value=([], [])),
        "init_asset_db": Mock(),
        "save_asset": Mock(),
        "calculate_asset_risk": Mock(return_value=42),
        "generate_remediation_plan": Mock(return_value=[]),
        "save_remediation_items": Mock(),
        "create_actions_from_remediation_plan": Mock(),
        "save_client_scan_summary": Mock(),
    }
    for service in ("securityhub", "guardduty", "config"):
        replacements[f"scan_client_{service}"] = Mock(
            return_value=([], [], {"status": "Not enabled"})
        )
    for name, replacement in replacements.items():
        monkeypatch.setattr(engine, name, replacement)
    return replacements


# Retain the real collectors before the fixture replaces module attributes.
REAL_IAM_SCAN = engine.scan_client_iam
REAL_S3_SCAN = engine.scan_client_s3


@pytest.mark.parametrize("client_key", [None, "", "   "])
def test_missing_tenant_fails_before_identity_or_storage(client_key):
    with pytest.raises(ValueError, match="client_key is required"):
        engine.run_client_scan(ROLE, client_key=client_key)
    engine.test_client_identity.assert_not_called()
    engine.init_asset_db.assert_not_called()
    engine.save_client_scan_summary.assert_not_called()


def test_failed_identity_stops_scanning_and_writes():
    engine.test_client_identity.return_value = {
        "status": "FAILED", "message": "Could not assume client role."
    }
    result = engine.run_client_scan(ROLE, client_key="tenant-a")
    assert result["scan_errors"] == ["Could not assume client role."]
    assert result["regions_scanned"] == []
    for name in (
        "scan_client_ec2", "scan_client_iam", "scan_client_s3",
        "scan_client_securityhub", "scan_client_guardduty",
        "scan_client_config", "init_asset_db", "save_asset",
        "save_remediation_items", "create_actions_from_remediation_plan",
        "save_client_scan_summary",
    ):
        getattr(engine, name).assert_not_called()


def test_regional_failure_preserves_other_region_and_tenant():
    instance = {
        "instance_id": "i-test", "region": "us-west-2",
        "state": "running", "private_ip": "10.0.0.1",
        "public_ip": None,
    }
    engine.scan_client_ec2.side_effect = [
        denied("DescribeInstances"), [instance]
    ]
    result = engine.run_client_scan(ROLE, client_key=" tenant-a ")
    assert result["ec2_instances"] == [instance]
    assert result["ec2_count"] == 1
    assert result["scan_errors"] == [
        "EC2 scan failed in us-east-1: AccessDenied: Denied"
    ]
    assert engine.scan_client_ec2.call_count == 2
    asset = engine.save_asset.call_args.args[0]
    assert asset["client_key"] == "tenant-a"  # pragma: allowlist secret
    assert asset["account_id"] == ACCOUNT
    assert asset["asset_id"] == "i-test"
    summary = engine.save_client_scan_summary.call_args.args[1]
    assert summary["ec2_count"] == 1
    assert summary["scan_errors"] == result["scan_errors"]
    engine.scan_client_config.assert_called_once_with(ROLE)


def test_iam_denials_remain_unknown_and_do_not_create_false_findings():
    iam = Mock()
    iam.can_paginate.return_value = False
    iam.list_users.return_value = {"Users": [{"UserName": "reader"}]}
    iam.list_mfa_devices.side_effect = denied("ListMFADevices")
    iam.list_access_keys.side_effect = denied("ListAccessKeys")
    engine.client_boto3_client.side_effect = None
    engine.client_boto3_client.return_value = iam
    users, errors = REAL_IAM_SCAN(ROLE)
    assert users[0]["mfa_enabled"] is None
    assert users[0]["active_access_keys"] is None
    assert len(errors) == 2
    assert all("AccessDenied" in error for error in errors)
    engine.scan_client_iam.return_value = (users, errors)
    result = engine.run_client_scan(ROLE, client_key="tenant-a")
    assert result["remediation_findings"] == []
    assert result["scan_errors"] == errors
    engine.save_remediation_items.assert_not_called()
    engine.create_actions_from_remediation_plan.assert_not_called()


def test_s3_denials_remain_unknown_and_do_not_create_false_findings():
    s3 = Mock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}
    s3.get_bucket_location.return_value = {"LocationConstraint": None}
    for method in (
        "get_public_access_block", "get_bucket_policy_status",
        "get_bucket_encryption",
    ):
        getattr(s3, method).side_effect = denied(method)
    engine.client_boto3_client.side_effect = None
    engine.client_boto3_client.return_value = s3
    buckets, errors = REAL_S3_SCAN(ROLE)
    bucket = buckets[0]
    assert bucket["region"] == "us-east-1"
    for field in (
        "public_access_block", "policy_public", "encryption_enabled"
    ):
        assert bucket[field] is None
    assert len(errors) == 3
    engine.scan_client_s3.return_value = (buckets, errors)
    result = engine.run_client_scan(ROLE, client_key="tenant-a")
    assert result["remediation_findings"] == []
    assert result["scan_errors"] == errors
    engine.create_actions_from_remediation_plan.assert_not_called()


@pytest.mark.parametrize("tenant", ["tenant-a", "tenant-b"])
def test_confirmed_finding_binds_remediation_to_requested_tenant(tenant):
    engine.scan_client_iam.return_value = ([{
        "user_name": "reader", "mfa_enabled": False,
        "active_access_keys": 0, "risk_score": 50,
        "state": "MFA: Missing; Active Keys: 0",
    }], [])
    plan = [{"finding": "MFA missing", "priority": "HIGH"}]
    engine.generate_remediation_plan.return_value = plan
    result = engine.run_client_scan(
        ROLE, client_name="Example Client", client_key=f" {tenant} "
    )
    assert result["remediation_findings"] == [{
        "cve_id": "IAM Risk - reader - MFA Missing",
        "priority": "HIGH", "risk_score": 75,
    }]
    engine.generate_remediation_plan.assert_called_once_with(
        result["remediation_findings"]
    )
    engine.save_remediation_items.assert_called_once_with(
        plan, client_key=tenant, aws_account_id=ACCOUNT,
        client_name="Example Client",
    )
    engine.create_actions_from_remediation_plan.assert_called_once_with(
        plan, aws_account_id=ACCOUNT,
        client_name="Example Client", role_arn=ROLE,
    )
    asset = engine.save_asset.call_args.args[0]
    assert asset["client_key"] == tenant
    assert asset["asset_id"] == f"{ACCOUNT}:iam:reader"
    assert result["remediation_count"] == 1
