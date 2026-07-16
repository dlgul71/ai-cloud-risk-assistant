from types import SimpleNamespace

import pytest

from remediation_azure_adapters import (
    AZURE_NSG_RULE_RESTRICTION_CONFIGURATION,
    AZURE_STORAGE_HARDENING_CONFIGURATION,
    build_nsg_rule_restriction_parameters,
    build_storage_account_hardening_parameters,
    execute_azure_nsg_rule_restriction,
    execute_azure_storage_account_hardening,
    parse_azure_nsg_resource_id,
    parse_azure_storage_resource_id,
)


RESOURCE_ID = (
    "/subscriptions/0792ff8b-1860-475a-9310-56c73cd71572"
    "/resourceGroups/dgs-sentinel-test-rg"
    "/providers/Microsoft.Storage"
    "/storageAccounts/dgssentineltest"
)

SUBSCRIPTION_ID = "0792ff8b-1860-475a-9310-56c73cd71572"


class FakePipelineResponse:
    def __init__(self, request_id, status_code=200):
        self.http_response = SimpleNamespace(
            headers={
                "x-ms-request-id": request_id,
            },
            status_code=status_code,
        )


class FakeStorageAccountsOperations:
    def __init__(self, verified_state=None):
        self.update_request = None
        self.get_request = None
        self.verified_state = verified_state or {
            "public_network_access": "Disabled",
            "enable_https_traffic_only": True,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "allow_blob_public_access": False,
        }

    def update(
        self,
        resource_group_name,
        account_name,
        parameters,
        **kwargs,
    ):
        self.update_request = {
            "resource_group_name": resource_group_name,
            "account_name": account_name,
            "parameters": parameters,
        }

        raw_response_hook = kwargs.get("raw_response_hook")

        if raw_response_hook:
            raw_response_hook(
                FakePipelineResponse(
                    "azure-update-request-id",
                )
            )

        return SimpleNamespace(**self.verified_state)

    def get_properties(
        self,
        resource_group_name,
        account_name,
        **kwargs,
    ):
        self.get_request = {
            "resource_group_name": resource_group_name,
            "account_name": account_name,
        }

        raw_response_hook = kwargs.get("raw_response_hook")

        if raw_response_hook:
            raw_response_hook(
                FakePipelineResponse(
                    "azure-verification-request-id",
                )
            )

        return SimpleNamespace(**self.verified_state)


class FakeStorageClient:
    def __init__(self, verified_state=None):
        self.storage_accounts = FakeStorageAccountsOperations(
            verified_state=verified_state,
        )


def test_parse_azure_storage_resource_id():
    target = parse_azure_storage_resource_id(
        RESOURCE_ID,
        expected_subscription_id=SUBSCRIPTION_ID,
    )

    assert target == {
        "subscription_id": SUBSCRIPTION_ID,
        "resource_group": "dgs-sentinel-test-rg",
        "provider_namespace": "Microsoft.Storage",
        "resource_type": "storageAccounts",
        "storage_account": "dgssentineltest",
        "resource_id": RESOURCE_ID,
    }


@pytest.mark.parametrize(
    "resource_id",
    [
        "",
        "not-an-azure-resource-id",
        (
            "/subscriptions/sub-1"
            "/resourceGroups/test-rg"
            "/providers/Microsoft.Compute"
            "/virtualMachines/test-vm"
        ),
    ],
)
def test_parse_azure_storage_resource_id_rejects_invalid_target(
    resource_id,
):
    with pytest.raises(ValueError):
        parse_azure_storage_resource_id(
            resource_id,
            expected_subscription_id=SUBSCRIPTION_ID,
        )


def test_parse_azure_storage_resource_id_rejects_wrong_subscription():
    with pytest.raises(
        ValueError,
        match="subscription",
    ):
        parse_azure_storage_resource_id(
            RESOURCE_ID,
            expected_subscription_id="different-subscription",
        )


def test_build_storage_hardening_parameters():
    parameters = build_storage_account_hardening_parameters()

    assert parameters.public_network_access == "Disabled"
    assert parameters.enable_https_traffic_only is True
    assert parameters.minimum_tls_version == "TLS1_2"
    assert parameters.allow_shared_key_access is False
    assert parameters.allow_blob_public_access is False


def test_execute_azure_storage_hardening_verifies_final_state():
    client = FakeStorageClient()

    result = execute_azure_storage_account_hardening(
        resource_id=RESOURCE_ID,
        expected_subscription_id=SUBSCRIPTION_ID,
        storage_client=client,
    )

    operations = client.storage_accounts
    parameters = operations.update_request["parameters"]

    assert operations.update_request[
        "resource_group_name"
    ] == "dgs-sentinel-test-rg"
    assert operations.update_request[
        "account_name"
    ] == "dgssentineltest"

    assert parameters.public_network_access == "Disabled"
    assert parameters.enable_https_traffic_only is True
    assert parameters.minimum_tls_version == "TLS1_2"
    assert parameters.allow_shared_key_access is False
    assert parameters.allow_blob_public_access is False

    assert operations.get_request == {
        "resource_group_name": "dgs-sentinel-test-rg",
        "account_name": "dgssentineltest",
    }

    assert result["status"] == "EXECUTED"
    assert result["verification_status"] == "VERIFIED"
    assert result["adapter"] == "AZURE_STORAGE_HARDENING"
    assert result["resource_type"] == "AZURE_STORAGE_ACCOUNT"
    assert result["resource_id"] == RESOURCE_ID
    assert result["subscription_id"] == SUBSCRIPTION_ID
    assert result["configuration"] == (
        AZURE_STORAGE_HARDENING_CONFIGURATION
    )
    assert result["verified_configuration"] == (
        AZURE_STORAGE_HARDENING_CONFIGURATION
    )
    assert result["request_id"] == "azure-update-request-id"
    assert result["verification_request_id"] == (
        "azure-verification-request-id"
    )
    assert result["http_status_code"] == 200
    assert result["verification_http_status_code"] == 200


def test_execute_azure_storage_hardening_fails_unverified_state():
    client = FakeStorageClient(
        verified_state={
            "public_network_access": "Enabled",
            "enable_https_traffic_only": True,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "allow_blob_public_access": False,
        }
    )

    result = execute_azure_storage_account_hardening(
        resource_id=RESOURCE_ID,
        expected_subscription_id=SUBSCRIPTION_ID,
        storage_client=client,
    )

    assert result["status"] == "FAILED"
    assert result["verification_status"] == "FAILED"
    assert "could not be verified" in result["message"]


def test_execute_azure_storage_hardening_requires_client():
    with pytest.raises(
        ValueError,
        match="authenticated Azure Storage client",
    ):
        execute_azure_storage_account_hardening(
            resource_id=RESOURCE_ID,
            expected_subscription_id=SUBSCRIPTION_ID,
            storage_client=None,
        )

NSG_RESOURCE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}"
    "/resourceGroups/dgs-sentinel-test-rg"
    "/providers/Microsoft.Network"
    "/networkSecurityGroups/dgs-sentinel-test-nsg"
)

NSG_RULE_NAME = "Allow-SSH-Internet"


class FakePoller:
    def __init__(self, value):
        self.value = value

    def result(self):
        return self.value


class FakeSecurityRulesOperations:
    def __init__(self, verified_access="Deny"):
        self.get_count = 0
        self.update_request = None
        self.verified_access = verified_access

    def get(
        self,
        resource_group_name,
        network_security_group_name,
        security_rule_name,
        **kwargs,
    ):
        self.get_count += 1

        raw_response_hook = kwargs.get("raw_response_hook")

        if raw_response_hook:
            request_id = (
                "azure-nsg-read-request-id"
                if self.get_count == 1
                else "azure-nsg-verification-request-id"
            )
            raw_response_hook(FakePipelineResponse(request_id))

        access = (
            "Allow"
            if self.get_count == 1
            else self.verified_access
        )

        return SimpleNamespace(
            name=security_rule_name,
            priority=100,
            protocol="Tcp",
            access=access,
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

        raw_response_hook = kwargs.get("raw_response_hook")

        if raw_response_hook:
            raw_response_hook(
                FakePipelineResponse(
                    "azure-nsg-update-request-id",
                )
            )

        return FakePoller(security_rule_parameters)


class FakeNetworkClient:
    def __init__(self, verified_access="Deny"):
        self.security_rules = FakeSecurityRulesOperations(
            verified_access=verified_access,
        )


def test_parse_azure_nsg_resource_id():
    target = parse_azure_nsg_resource_id(
        NSG_RESOURCE_ID,
        expected_subscription_id=SUBSCRIPTION_ID,
    )

    assert target == {
        "subscription_id": SUBSCRIPTION_ID,
        "resource_group": "dgs-sentinel-test-rg",
        "provider_namespace": "Microsoft.Network",
        "resource_type": "networkSecurityGroups",
        "network_security_group": "dgs-sentinel-test-nsg",
        "resource_id": NSG_RESOURCE_ID,
    }


@pytest.mark.parametrize(
    "resource_id",
    [
        "",
        "not-an-azure-resource-id",
        (
            f"/subscriptions/{SUBSCRIPTION_ID}"
            "/resourceGroups/test-rg"
            "/providers/Microsoft.Compute"
            "/virtualMachines/test-vm"
        ),
    ],
)
def test_parse_azure_nsg_resource_id_rejects_invalid_target(
    resource_id,
):
    with pytest.raises(ValueError):
        parse_azure_nsg_resource_id(
            resource_id,
            expected_subscription_id=SUBSCRIPTION_ID,
        )


def test_parse_azure_nsg_resource_id_rejects_wrong_subscription():
    with pytest.raises(ValueError, match="subscription"):
        parse_azure_nsg_resource_id(
            NSG_RESOURCE_ID,
            expected_subscription_id="different-subscription",
        )


def test_build_nsg_rule_restriction_parameters():
    existing_rule = SimpleNamespace(
        name=NSG_RULE_NAME,
        priority=100,
        protocol="Tcp",
        access="Allow",
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

    parameters = build_nsg_rule_restriction_parameters(
        existing_rule
    )

    assert parameters.access == "Deny"
    assert parameters.priority == 100
    assert parameters.protocol == "Tcp"
    assert parameters.direction == "Inbound"
    assert parameters.destination_port_range == "22"
    assert parameters.source_address_prefix == "Internet"


def test_execute_azure_nsg_rule_restriction_verifies_final_state():
    client = FakeNetworkClient()

    result = execute_azure_nsg_rule_restriction(
        resource_id=NSG_RESOURCE_ID,
        rule_name=NSG_RULE_NAME,
        expected_subscription_id=SUBSCRIPTION_ID,
        network_client=client,
    )

    operations = client.security_rules
    parameters = operations.update_request["parameters"]

    assert operations.update_request == {
        "resource_group_name": "dgs-sentinel-test-rg",
        "network_security_group_name": "dgs-sentinel-test-nsg",
        "security_rule_name": NSG_RULE_NAME,
        "parameters": parameters,
    }

    assert parameters.access == "Deny"
    assert result["status"] == "EXECUTED"
    assert result["verification_status"] == "VERIFIED"
    assert result["adapter"] == "AZURE_NSG_RULE_RESTRICTION"
    assert result["resource_type"] == (
        "AZURE_NETWORK_SECURITY_GROUP_RULE"
    )
    assert result["resource_id"] == NSG_RESOURCE_ID
    assert result["rule_name"] == NSG_RULE_NAME
    assert result["subscription_id"] == SUBSCRIPTION_ID
    assert result["configuration"] == (
        AZURE_NSG_RULE_RESTRICTION_CONFIGURATION
    )
    assert result["verified_configuration"] == {
        "access": "Deny",
    }
    assert result["request_id"] == "azure-nsg-update-request-id"
    assert result["verification_request_id"] == (
        "azure-nsg-verification-request-id"
    )


def test_execute_azure_nsg_rule_restriction_fails_unverified_state():
    client = FakeNetworkClient(verified_access="Allow")

    result = execute_azure_nsg_rule_restriction(
        resource_id=NSG_RESOURCE_ID,
        rule_name=NSG_RULE_NAME,
        expected_subscription_id=SUBSCRIPTION_ID,
        network_client=client,
    )

    assert result["status"] == "FAILED"
    assert result["verification_status"] == "FAILED"
    assert "could not be verified" in result["message"]


def test_execute_azure_nsg_rule_restriction_requires_client():
    with pytest.raises(
        ValueError,
        match="authenticated Azure Network client",
    ):
        execute_azure_nsg_rule_restriction(
            resource_id=NSG_RESOURCE_ID,
            rule_name=NSG_RULE_NAME,
            expected_subscription_id=SUBSCRIPTION_ID,
            network_client=None,
        )
