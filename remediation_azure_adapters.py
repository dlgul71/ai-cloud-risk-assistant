"""Guarded Azure remediation adapters for DGS Sentinel AI."""

from __future__ import annotations

from typing import Any

try:
    from azure.mgmt.storage.models import (
        StorageAccountUpdateParameters,
    )
except ImportError:  # pragma: no cover
    StorageAccountUpdateParameters = None


AZURE_STORAGE_HARDENING_CONFIGURATION = {
    "public_network_access": "Disabled",
    "enable_https_traffic_only": True,
    "minimum_tls_version": "TLS1_2",
    "allow_shared_key_access": False,
    "allow_blob_public_access": False,
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
