"""Azure resource discovery for DGS Sentinel AI."""

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient


def discover_azure_resources(
    credential,
    subscription_id,
):
    """Discover core Azure resources for a subscription."""

    if credential is None:
        raise ValueError("Azure credential is required.")

    if not subscription_id:
        raise ValueError("Azure subscription ID is required.")

    resource_client = ResourceManagementClient(
        credential,
        subscription_id,
    )
    compute_client = ComputeManagementClient(
        credential,
        subscription_id,
    )
    storage_client = StorageManagementClient(
        credential,
        subscription_id,
    )

    resource_groups = [
        {
            "name": group.name,
            "location": group.location,
            "id": group.id,
        }
        for group in resource_client.resource_groups.list()
    ]

    virtual_machines = [
        {
            "name": vm.name,
            "location": vm.location,
            "resource_group": _resource_group_from_id(vm.id),
            "vm_size": getattr(
                getattr(vm, "hardware_profile", None),
                "vm_size",
                None,
            ),
            "id": vm.id,
        }
        for vm in compute_client.virtual_machines.list_all()
    ]

    storage_accounts = [
        {
            "name": account.name,
            "location": account.location,
            "resource_group": _resource_group_from_id(account.id),
            "kind": str(account.kind),
            "sku": getattr(
                getattr(account, "sku", None),
                "name",
                None,
            ),
            "https_only": getattr(
                account,
                "enable_https_traffic_only",
                None,
            ),
            "minimum_tls_version": str(
                getattr(account, "minimum_tls_version", None)
                or ""
            ),
            "allow_shared_key_access": getattr(
                account,
                "allow_shared_key_access",
                None,
            ),
            "public_network_access": str(
                getattr(account, "public_network_access", None)
                or ""
            ),
            "network_default_action": str(
                getattr(
                    getattr(account, "network_rule_set", None),
                    "default_action",
                    None,
                )
                or ""
            ),
            "network_bypass": str(
                getattr(
                    getattr(account, "network_rule_set", None),
                    "bypass",
                    None,
                )
                or ""
            ),
            "id": account.id,
        }
        for account in storage_client.storage_accounts.list()
    ]

    return {
        "subscription_id": subscription_id,
        "resource_groups": resource_groups,
        "virtual_machines": virtual_machines,
        "storage_accounts": storage_accounts,
        "summary": {
            "resource_groups": len(resource_groups),
            "virtual_machines": len(virtual_machines),
            "storage_accounts": len(storage_accounts),
        },
    }


def _resource_group_from_id(resource_id):
    """Extract the resource-group name from an Azure resource ID."""

    if not resource_id:
        return None

    parts = [
        part
        for part in str(resource_id).split("/")
        if part
    ]

    for index, part in enumerate(parts):
        if (
            part.lower() == "resourcegroups"
            and index + 1 < len(parts)
        ):
            return parts[index + 1]

    return None
