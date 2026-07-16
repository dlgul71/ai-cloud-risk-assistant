"""Guarded Azure remediation adapters for DGS Sentinel AI."""

from __future__ import annotations

from typing import Any

try:
    from azure.mgmt.storage.models import (
        StorageAccountUpdateParameters,
    )
except ImportError:  # pragma: no cover
    StorageAccountUpdateParameters = None

try:
    from azure.mgmt.network.models import SecurityRule
except ImportError:  # pragma: no cover
    SecurityRule = None


AZURE_STORAGE_HARDENING_CONFIGURATION = {
    "public_network_access": "Disabled",
    "enable_https_traffic_only": True,
    "minimum_tls_version": "TLS1_2",
    "allow_shared_key_access": False,
    "allow_blob_public_access": False,
}

AZURE_NSG_RULE_RESTRICTION_CONFIGURATION = {
    "access": "Deny",
}


def parse_azure_storage_resource_id(
    resource_id: str,
    expected_subscription_id: str,
) -> dict[str, str]:
    """Validate and parse an Azure Storage Account resource ID."""

    normalized_resource_id = str(resource_id or "").strip()
    normalized_expected_subscription = str(
        expected_subscription_id or ""
    ).strip()

    if not normalized_resource_id:
        raise ValueError(
            "An Azure Storage Account resource ID is required."
        )

    if not normalized_expected_subscription:
        raise ValueError(
            "An expected Azure subscription ID is required."
        )

    segments = [
        segment
        for segment in normalized_resource_id.split("/")
        if segment
    ]

    if len(segments) != 8:
        raise ValueError(
            "The Azure Storage Account resource ID is invalid."
        )

    keys = [segment.lower() for segment in segments]

    if (
        keys[0] != "subscriptions"
        or keys[2] != "resourcegroups"
        or keys[4] != "providers"
        or keys[5] != "microsoft.storage"
        or keys[6] != "storageaccounts"
    ):
        raise ValueError(
            "The resource ID must identify an Azure Storage Account."
        )

    subscription_id = segments[1]
    resource_group = segments[3]
    provider_namespace = segments[5]
    resource_type = segments[6]
    storage_account = segments[7]

    if (
        subscription_id.lower()
        != normalized_expected_subscription.lower()
    ):
        raise ValueError(
            "The Azure resource subscription does not match the "
            "expected subscription."
        )

    if not resource_group or not storage_account:
        raise ValueError(
            "The Azure Storage Account resource ID is incomplete."
        )

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "provider_namespace": provider_namespace,
        "resource_type": resource_type,
        "storage_account": storage_account,
        "resource_id": normalized_resource_id,
    }



def parse_azure_nsg_resource_id(
    resource_id: str,
    expected_subscription_id: str,
) -> dict[str, str]:
    """Validate and parse an Azure Network Security Group resource ID."""

    normalized_resource_id = str(resource_id or "").strip()
    normalized_expected_subscription = str(
        expected_subscription_id or ""
    ).strip()

    if not normalized_resource_id:
        raise ValueError(
            "An Azure Network Security Group resource ID is required."
        )

    if not normalized_expected_subscription:
        raise ValueError(
            "An expected Azure subscription ID is required."
        )

    segments = [
        segment
        for segment in normalized_resource_id.split("/")
        if segment
    ]

    if len(segments) != 8:
        raise ValueError(
            "The Azure Network Security Group resource ID is invalid."
        )

    keys = [segment.lower() for segment in segments]

    if (
        keys[0] != "subscriptions"
        or keys[2] != "resourcegroups"
        or keys[4] != "providers"
        or keys[5] != "microsoft.network"
        or keys[6] != "networksecuritygroups"
    ):
        raise ValueError(
            "The resource ID must identify an Azure "
            "Network Security Group."
        )

    subscription_id = segments[1]
    resource_group = segments[3]
    provider_namespace = segments[5]
    resource_type = segments[6]
    network_security_group = segments[7]

    if (
        subscription_id.lower()
        != normalized_expected_subscription.lower()
    ):
        raise ValueError(
            "The Azure resource subscription does not match the "
            "expected subscription."
        )

    if not resource_group or not network_security_group:
        raise ValueError(
            "The Azure Network Security Group resource ID is incomplete."
        )

    return {
        "subscription_id": subscription_id,
        "resource_group": resource_group,
        "provider_namespace": provider_namespace,
        "resource_type": resource_type,
        "network_security_group": network_security_group,
        "resource_id": normalized_resource_id,
    }


def build_nsg_rule_restriction_parameters(
    existing_rule: Any,
) -> Any:
    """Build a deny rule while preserving the existing rule scope."""

    if SecurityRule is None:
        raise RuntimeError(
            "The Azure Network management SDK is required."
        )

    if existing_rule is None:
        raise ValueError(
            "The existing Azure NSG security rule is required."
        )

    return SecurityRule(
        name=getattr(existing_rule, "name", None),
        description=getattr(existing_rule, "description", None),
        protocol=getattr(existing_rule, "protocol", None),
        source_port_range=getattr(
            existing_rule,
            "source_port_range",
            None,
        ),
        source_port_ranges=getattr(
            existing_rule,
            "source_port_ranges",
            None,
        ),
        destination_port_range=getattr(
            existing_rule,
            "destination_port_range",
            None,
        ),
        destination_port_ranges=getattr(
            existing_rule,
            "destination_port_ranges",
            None,
        ),
        source_address_prefix=getattr(
            existing_rule,
            "source_address_prefix",
            None,
        ),
        source_address_prefixes=getattr(
            existing_rule,
            "source_address_prefixes",
            None,
        ),
        source_application_security_groups=getattr(
            existing_rule,
            "source_application_security_groups",
            None,
        ),
        destination_address_prefix=getattr(
            existing_rule,
            "destination_address_prefix",
            None,
        ),
        destination_address_prefixes=getattr(
            existing_rule,
            "destination_address_prefixes",
            None,
        ),
        destination_application_security_groups=getattr(
            existing_rule,
            "destination_application_security_groups",
            None,
        ),
        access="Deny",
        priority=getattr(existing_rule, "priority", None),
        direction=getattr(existing_rule, "direction", None),
    )


def execute_azure_nsg_rule_restriction(
    resource_id: str,
    rule_name: str,
    expected_subscription_id: str,
    network_client: Any,
) -> dict[str, Any]:
    """Change an Azure NSG security rule to Deny and verify it."""

    if network_client is None:
        raise ValueError(
            "An authenticated Azure Network client is required "
            "for live execution."
        )

    normalized_rule_name = str(rule_name or "").strip()

    if not normalized_rule_name:
        raise ValueError(
            "An Azure NSG security rule name is required."
        )

    target = parse_azure_nsg_resource_id(
        resource_id=resource_id,
        expected_subscription_id=expected_subscription_id,
    )

    read_metadata: dict[str, Any] = {}
    update_metadata: dict[str, Any] = {}
    verification_metadata: dict[str, Any] = {}

    existing_rule = network_client.security_rules.get(
        resource_group_name=target["resource_group"],
        network_security_group_name=(
            target["network_security_group"]
        ),
        security_rule_name=normalized_rule_name,
        raw_response_hook=_capture_azure_response(
            read_metadata
        ),
    )

    parameters = build_nsg_rule_restriction_parameters(
        existing_rule
    )

    poller = network_client.security_rules.begin_create_or_update(
        resource_group_name=target["resource_group"],
        network_security_group_name=(
            target["network_security_group"]
        ),
        security_rule_name=normalized_rule_name,
        security_rule_parameters=parameters,
        raw_response_hook=_capture_azure_response(
            update_metadata
        ),
    )

    poller.result()

    verified_rule = network_client.security_rules.get(
        resource_group_name=target["resource_group"],
        network_security_group_name=(
            target["network_security_group"]
        ),
        security_rule_name=normalized_rule_name,
        raw_response_hook=_capture_azure_response(
            verification_metadata
        ),
    )

    verified_configuration = {
        "access": str(
            getattr(verified_rule, "access", "") or ""
        ),
    }

    is_verified = (
        verified_configuration
        == AZURE_NSG_RULE_RESTRICTION_CONFIGURATION
    )

    result = {
        "status": "EXECUTED" if is_verified else "FAILED",
        "verification_status": (
            "VERIFIED" if is_verified else "FAILED"
        ),
        "adapter": "AZURE_NSG_RULE_RESTRICTION",
        "resource_type": "AZURE_NETWORK_SECURITY_GROUP_RULE",
        "resource_id": target["resource_id"],
        "rule_name": normalized_rule_name,
        "subscription_id": target["subscription_id"],
        "configuration": dict(
            AZURE_NSG_RULE_RESTRICTION_CONFIGURATION
        ),
        "verified_configuration": verified_configuration,
        "request_id": update_metadata.get("request_id"),
        "verification_request_id": (
            verification_metadata.get("request_id")
        ),
        "http_status_code": update_metadata.get(
            "http_status_code"
        ),
        "verification_http_status_code": (
            verification_metadata.get("http_status_code")
        ),
    }

    if is_verified:
        result["message"] = (
            "Azure NSG security rule restriction was applied "
            "and verified."
        )
    else:
        result["message"] = (
            "Azure NSG security rule restriction was requested "
            "but the final configuration could not be verified."
        )

    return result

def build_storage_account_hardening_parameters() -> Any:
    """Build Azure Storage Account security-hardening parameters."""

    if StorageAccountUpdateParameters is None:
        raise RuntimeError(
            "The Azure Storage management SDK is required."
        )

    return StorageAccountUpdateParameters(
        public_network_access="Disabled",
        enable_https_traffic_only=True,
        minimum_tls_version="TLS1_2",
        allow_shared_key_access=False,
        allow_blob_public_access=False,
    )


def _capture_azure_response(
    metadata: dict[str, Any],
):
    """Return a raw-response hook that captures Azure request metadata."""

    def hook(pipeline_response: Any) -> None:
        http_response = getattr(
            pipeline_response,
            "http_response",
            None,
        )

        if http_response is None:
            return

        headers = getattr(http_response, "headers", {}) or {}

        metadata["request_id"] = (
            headers.get("x-ms-request-id")
            or headers.get("X-MS-REQUEST-ID")
        )
        metadata["http_status_code"] = getattr(
            http_response,
            "status_code",
            None,
        )

    return hook


def _storage_configuration(resource: Any) -> dict[str, Any]:
    """Extract the verified hardening fields from a storage resource."""

    return {
        field_name: getattr(resource, field_name, None)
        for field_name in AZURE_STORAGE_HARDENING_CONFIGURATION
    }


def execute_azure_storage_account_hardening(
    resource_id: str,
    expected_subscription_id: str,
    storage_client: Any,
) -> dict[str, Any]:
    """Harden an Azure Storage Account and verify its final state."""

    if storage_client is None:
        raise ValueError(
            "An authenticated Azure Storage client is required "
            "for live execution."
        )

    target = parse_azure_storage_resource_id(
        resource_id=resource_id,
        expected_subscription_id=expected_subscription_id,
    )

    parameters = build_storage_account_hardening_parameters()

    update_metadata: dict[str, Any] = {}
    verification_metadata: dict[str, Any] = {}

    storage_client.storage_accounts.update(
        resource_group_name=target["resource_group"],
        account_name=target["storage_account"],
        parameters=parameters,
        raw_response_hook=_capture_azure_response(
            update_metadata
        ),
    )

    verified_resource = (
        storage_client.storage_accounts.get_properties(
            resource_group_name=target["resource_group"],
            account_name=target["storage_account"],
            raw_response_hook=_capture_azure_response(
                verification_metadata
            ),
        )
    )

    verified_configuration = _storage_configuration(
        verified_resource
    )

    is_verified = all(
        verified_configuration.get(field_name)
        == expected_value
        for field_name, expected_value
        in AZURE_STORAGE_HARDENING_CONFIGURATION.items()
    )

    result = {
        "status": "EXECUTED" if is_verified else "FAILED",
        "verification_status": (
            "VERIFIED" if is_verified else "FAILED"
        ),
        "adapter": "AZURE_STORAGE_HARDENING",
        "resource_type": "AZURE_STORAGE_ACCOUNT",
        "resource_id": target["resource_id"],
        "subscription_id": target["subscription_id"],
        "configuration": dict(
            AZURE_STORAGE_HARDENING_CONFIGURATION
        ),
        "verified_configuration": verified_configuration,
        "request_id": update_metadata.get("request_id"),
        "verification_request_id": (
            verification_metadata.get("request_id")
        ),
        "http_status_code": update_metadata.get(
            "http_status_code"
        ),
        "verification_http_status_code": (
            verification_metadata.get("http_status_code")
        ),
    }

    if is_verified:
        result["message"] = (
            "Azure Storage Account security hardening was "
            "applied and verified."
        )
    else:
        result["message"] = (
            "Azure Storage Account security hardening was "
            "requested but the final configuration could not "
            "be verified."
        )

    return result
