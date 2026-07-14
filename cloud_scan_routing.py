"""Cloud-provider routing helpers for DGS Sentinel AI scans."""

from datetime import datetime, timezone


AZURE_RESOURCE_TYPES = (
    ("Azure Virtual Machine", "virtual_machines"),
    ("Azure Storage Account", "storage_accounts"),
    ("Azure Network Security Group", "network_security_groups"),
    ("Azure Public IP Address", "public_ip_addresses"),
    ("Azure Network Interface", "network_interfaces"),
)


def normalize_cloud_provider(value):
    """Return a normalized supported cloud-provider name."""
    provider = str(value or "AWS").strip().upper()

    if provider not in {"AWS", "AZURE"}:
        return "AWS"

    return provider


def summarize_azure_resources(discovery_result):
    """Return Azure discovery resource counts."""
    discovery_result = (
        discovery_result
        if isinstance(discovery_result, dict)
        else {}
    )

    return {
        key: len(discovery_result.get(key, []) or [])
        for _, key in AZURE_RESOURCE_TYPES
    }


def build_azure_snapshot_assets(
    discovery_result,
    subscription_id,
    scanned_at=None,
):
    """Convert Azure discovery resources into snapshot asset records."""
    if not isinstance(discovery_result, dict):
        return []

    scan_time = scanned_at or datetime.now(
        timezone.utc
    ).isoformat()

    assets = []

    for asset_type, collection_name in AZURE_RESOURCE_TYPES:
        resources = discovery_result.get(
            collection_name,
            [],
        ) or []

        for resource_number, resource in enumerate(
            resources,
            start=1,
        ):
            if not isinstance(resource, dict):
                continue

            resource_id = (
                resource.get("id")
                or resource.get("resource_id")
                or resource.get("name")
                or f"{collection_name}-{resource_number}"
            )

            resource_name = (
                resource.get("name")
                or str(resource_id).rstrip("/").split("/")[-1]
            )

            public_ip = (
                resource.get("ip_address")
                or resource.get("public_ip_address")
                or resource.get("public_ip")
            )

            private_ip = (
                resource.get("private_ip_address")
                or resource.get("private_ip")
            )

            state = (
                resource.get("power_state")
                or resource.get("provisioning_state")
                or resource.get("state")
                or "discovered"
            )

            assets.append(
                {
                    "asset_id": str(resource_id),
                    "asset_type": asset_type,
                    "account_id": str(subscription_id or ""),
                    "region": resource.get(
                        "location",
                        "global",
                    ),
                    "hostname": str(resource_name),
                    "private_ip": private_ip,
                    "public_ip": public_ip,
                    "state": str(state),
                    "risk_score": 0,
                    "last_scan": scan_time,
                }
            )

    return assets
