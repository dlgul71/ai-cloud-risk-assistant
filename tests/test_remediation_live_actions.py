from dataclasses import replace
from types import SimpleNamespace

import remediation_guardrails
from remediation_live_actions import execute_controlled_action


S3_ACTION = "Generate S3 Exposure Remediation Task"
IAM_ACTION = "Generate IAM MFA and Access Key Review Task"
AZURE_STORAGE_ACTION = "Generate Azure Storage Hardening Task"
AZURE_NSG_ACTION = "Generate Azure NSG Rule Restriction Task"
AZURE_SUBSCRIPTION_ID = "0792ff8b-1860-475a-9310-56c73cd71572"
AZURE_NSG_RULE_NAME = "Allow-SSH-Internet"
AZURE_NSG_RESOURCE_ID = (
    f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
    "/resourceGroups/dgs-sentinel-test-rg"
    "/providers/Microsoft.Network"
    "/networkSecurityGroups/dgs-sentinel-test-nsg"
)
AZURE_RESOURCE_ID = (
    f"/subscriptions/{AZURE_SUBSCRIPTION_ID}"
    "/resourceGroups/dgs-sentinel-test-rg"
    "/providers/Microsoft.Storage"
    "/storageAccounts/dgssentineltest"
)
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

    def get_public_access_block(self, **kwargs):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "ResponseMetadata": {
                "RequestId": "phase-18-verification-request",
                "HTTPStatusCode": 200,
            },
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

class FakeAzurePipelineResponse:
    def __init__(self, request_id, status_code=200):
        self.http_response = SimpleNamespace(
            headers={"x-ms-request-id": request_id},
            status_code=status_code,
        )


class FakeAzureStorageOperations:
    def update(
        self,
        resource_group_name,
        account_name,
        parameters,
        **kwargs,
    ):
        hook = kwargs.get("raw_response_hook")

        if hook:
            hook(
                FakeAzurePipelineResponse(
                    "azure-live-update-request",
                )
            )

        return SimpleNamespace(
            public_network_access="Disabled",
            enable_https_traffic_only=True,
            minimum_tls_version="TLS1_2",
            allow_shared_key_access=False,
            allow_blob_public_access=False,
        )

    def get_properties(
        self,
        resource_group_name,
        account_name,
        **kwargs,
    ):
        hook = kwargs.get("raw_response_hook")

        if hook:
            hook(
                FakeAzurePipelineResponse(
                    "azure-live-verification-request",
                )
            )

        return SimpleNamespace(
            public_network_access="Disabled",
            enable_https_traffic_only=True,
            minimum_tls_version="TLS1_2",
            allow_shared_key_access=False,
            allow_blob_public_access=False,
        )


class FakeAzureStorageClient:
    def __init__(self):
        self.storage_accounts = FakeAzureStorageOperations()


def test_azure_storage_simulation_does_not_require_client():
    result = execute_controlled_action(
        action_type=AZURE_STORAGE_ACTION,
        finding=f"Azure Storage Risk - {AZURE_RESOURCE_ID}",
        approval_status="Approved",
        execution_mode="Simulation",
    )

    assert result["status"] == "SIMULATED"
    assert result["adapter"] == "AZURE_STORAGE_HARDENING"


def test_live_azure_storage_action_executes_with_injected_client(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=AZURE_STORAGE_ACTION,
        finding=f"Azure Storage Risk - {AZURE_RESOURCE_ID}",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        expected_subscription_id=AZURE_SUBSCRIPTION_ID,
        azure_storage_client=FakeAzureStorageClient(),
    )

    assert result["status"] == "EXECUTED"
    assert result["verification_status"] == "VERIFIED"
    assert result["mode"] == "Live"
    assert result["adapter"] == "AZURE_STORAGE_HARDENING"
    assert result["resource_id"] == AZURE_RESOURCE_ID
    assert result["subscription_id"] == AZURE_SUBSCRIPTION_ID
    assert result["request_id"] == "azure-live-update-request"
    assert result["verification_request_id"] == (
        "azure-live-verification-request"
    )


def test_live_azure_storage_action_requires_subscription_id(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=AZURE_STORAGE_ACTION,
        finding=f"Azure Storage Risk - {AZURE_RESOURCE_ID}",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        azure_storage_client=FakeAzureStorageClient(),
    )

    assert result["status"] == "BLOCKED"
    assert "subscription" in result["message"].lower()


class FakeAzureNetworkPoller:
    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value


class FakeAzureSecurityRulesOperations:
    def __init__(self):
        self.get_count = 0
        self.update_request = None

    def get(
        self,
        resource_group_name,
        network_security_group_name,
        security_rule_name,
        **kwargs,
    ):
        self.get_count += 1

        hook = kwargs.get("raw_response_hook")

        if hook:
            request_id = (
                "azure-nsg-read-request"
                if self.get_count == 1
                else "azure-nsg-verification-request"
            )
            hook(FakeAzurePipelineResponse(request_id))

        return SimpleNamespace(
            name=security_rule_name,
            priority=100,
            protocol="Tcp",
            access="Allow" if self.get_count == 1 else "Deny",
            direction="Inbound",
            source_port_range="*",
            source_port_ranges=None,
            destination_port_range="22",
            destination_port_ranges=None,
            source_address_prefix="Internet",
            source_address_prefixes=None,
            destination_address_prefix="*",
            destination_address_prefixes=None,
            description="Temporary test rule",
        )

    def begin_create_or_update(
        self,
        resource_group_name,
        network_security_group_name,
        security_rule_name,
        security_rule_parameters,
        **kwargs,
    ):
        self.update_request = {
            "resource_group_name": resource_group_name,
            "network_security_group_name": (
                network_security_group_name
            ),
            "security_rule_name": security_rule_name,
            "parameters": security_rule_parameters,
        }

        hook = kwargs.get("raw_response_hook")

        if hook:
            hook(
                FakeAzurePipelineResponse(
                    "azure-nsg-update-request",
                )
            )

        return FakeAzureNetworkPoller(
            security_rule_parameters
        )


class FakeAzureNetworkClient:
    def __init__(self):
        self.security_rules = FakeAzureSecurityRulesOperations()


def test_azure_nsg_simulation_does_not_require_client():
    result = execute_controlled_action(
        action_type=AZURE_NSG_ACTION,
        finding=(
            f"Azure NSG Risk - {AZURE_NSG_RESOURCE_ID} "
            f"| Rule: {AZURE_NSG_RULE_NAME}"
        ),
        approval_status="Approved",
        execution_mode="Simulation",
    )

    assert result["status"] == "SIMULATED"
    assert result["adapter"] == "AZURE_NSG_RULE_RESTRICTION"


def test_live_azure_nsg_action_executes_with_injected_client(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=AZURE_NSG_ACTION,
        finding=(
            f"Azure NSG Risk - {AZURE_NSG_RESOURCE_ID} "
            f"| Rule: {AZURE_NSG_RULE_NAME}"
        ),
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        expected_subscription_id=AZURE_SUBSCRIPTION_ID,
        azure_network_client=FakeAzureNetworkClient(),
    )

    assert result["status"] == "EXECUTED"
    assert result["verification_status"] == "VERIFIED"
    assert result["mode"] == "Live"
    assert result["adapter"] == "AZURE_NSG_RULE_RESTRICTION"
    assert result["resource_id"] == AZURE_NSG_RESOURCE_ID
    assert result["rule_name"] == AZURE_NSG_RULE_NAME
    assert result["subscription_id"] == AZURE_SUBSCRIPTION_ID
    assert result["request_id"] == "azure-nsg-update-request"
    assert result["verification_request_id"] == (
        "azure-nsg-verification-request"
    )


def test_live_azure_nsg_action_requires_subscription_id(
    monkeypatch,
):
    enable_live_remediation(monkeypatch)

    result = execute_controlled_action(
        action_type=AZURE_NSG_ACTION,
        finding=(
            f"Azure NSG Risk - {AZURE_NSG_RESOURCE_ID} "
            f"| Rule: {AZURE_NSG_RULE_NAME}"
        ),
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase=CONFIRMATION,
        azure_network_client=FakeAzureNetworkClient(),
    )

    assert result["status"] == "BLOCKED"
    assert "subscription" in result["message"].lower()
