from dataclasses import replace

import remediation_guardrails
from remediation_live_actions import execute_controlled_action


S3_ACTION = "Generate S3 Exposure Remediation Task"
IAM_ACTION = "Generate IAM MFA and Access Key Review Task"
CONFIRMATION = "AUTHORIZE LIVE AWS REMEDIATION"


class FakeS3Client:
    def __init__(self):
        self.request = None

    def put_public_access_block(self, **kwargs):
        self.request = kwargs

        return {
            "ResponseMetadata": {
                "RequestId": "phase-17-request",
                "HTTPStatusCode": 200,
            }
        }


def enable_live_remediation(monkeypatch):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=True,
        ),
    )


def test_simulation_does_not_require_aws_client():
    result = execute_controlled_action(
        action_type=S3_ACTION,
        finding="S3 Risk - example-security-bucket",
        approval_status="Approved",
        execution_mode="Simulation",
    )

    assert result["status"] == "SIMULATED"
    assert result["adapter"] == "S3_BLOCK_PUBLIC_ACCESS"


def test_live_s3_action_remains_blocked_when_feature_disabled(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=False,
        ),
    )

    result = execute_controlled_action(
        action_type=S3_ACTION,
        finding="S3 Risk - example-security-bucket",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        expected_account_id="123456789012",
        s3_client=FakeS3Client(),
    )

    assert result["status"] == "BLOCKED"
    assert "disabled" in result["message"].lower()


def test_live_s3_action_executes_with_injected_client(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)
    client = FakeS3Client()

    result = execute_controlled_action(
        action_type=S3_ACTION,
        finding="S3 Risk - example-security-bucket",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        expected_account_id="123456789012",
        s3_client=client,
    )

    assert result["status"] == "EXECUTED"
    assert result["mode"] == "Live"
    assert result["resource_id"] == "example-security-bucket"
    assert result["expected_bucket_owner"] == "123456789012"
    assert result["request_id"] == "phase-17-request"


def test_live_s3_action_requires_expected_account_id(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=S3_ACTION,
        finding="S3 Risk - example-security-bucket",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        s3_client=FakeS3Client(),
    )

    assert result["status"] == "BLOCKED"
    assert "account" in result["message"].lower()


def test_non_s3_live_adapter_remains_blocked(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=IAM_ACTION,
        finding="IAM Risk - example-user",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        expected_account_id="123456789012",
    )

    assert result["status"] == "BLOCKED"
    assert "not enabled for live execution" in result["message"].lower()
