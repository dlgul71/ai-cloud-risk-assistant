"""Azure resource discovery for DGS Sentinel AI."""

from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
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
    network_client = NetworkManagementClient(
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
            "network_interface_ids": _reference_ids(
                getattr(
                    getattr(vm, "network_profile", None),
                    "network_interfaces",
                    None,
                )
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

    network_security_groups = [
        _serialize_network_security_group(network_security_group)
        for network_security_group
        in network_client.network_security_groups.list_all()
    ]

    public_ip_addresses = [
        _serialize_public_ip_address(public_ip_address)
        for public_ip_address
        in network_client.public_ip_addresses.list_all()
    ]

    network_interfaces = [
        _serialize_network_interface(network_interface)
        for network_interface
        in network_client.network_interfaces.list_all()
    ]

    return {
        "subscription_id": subscription_id,
        "resource_groups": resource_groups,
        "virtual_machines": virtual_machines,
        "storage_accounts": storage_accounts,
        "network_security_groups": network_security_groups,
        "public_ip_addresses": public_ip_addresses,
        "network_interfaces": network_interfaces,
        "summary": {
            "resource_groups": len(resource_groups),
            "virtual_machines": len(virtual_machines),
            "storage_accounts": len(storage_accounts),
            "network_security_groups": len(
                network_security_groups
            ),
            "public_ip_addresses": len(
                public_ip_addresses
            ),
            "network_interfaces": len(network_interfaces),
        },
    }


def _serialize_network_security_group(
    network_security_group,
):
    """Convert an Azure NSG object to a serializable dictionary."""

    rules = getattr(
        network_security_group,
        "security_rules",
        None,
    ) or []

    return {
        "name": network_security_group.name,
        "location": network_security_group.location,
        "resource_group": _resource_group_from_id(
            network_security_group.id
        ),
        "security_rules": [
            {
                "name": rule.name,
                "access": _string_or_none(
                    getattr(rule, "access", None)
                ),
                "direction": _string_or_none(
                    getattr(rule, "direction", None)
                ),
                "priority": getattr(rule, "priority", None),
                "protocol": _string_or_none(
                    getattr(rule, "protocol", None)
                ),
                "source_address_prefix": getattr(
                    rule,
                    "source_address_prefix",
                    None,
                ),
                "source_address_prefixes": getattr(
                    rule,
                    "source_address_prefixes",
                    None,
                ),
                "destination_port_range": getattr(
                    rule,
                    "destination_port_range",
                    None,
                ),
                "destination_port_ranges": getattr(
                    rule,
                    "destination_port_ranges",
                    None,
                ),
            }
            for rule in rules
        ],
        "id": network_security_group.id,
    }


def _serialize_public_ip_address(public_ip_address):
    """Convert an Azure public IP object to a dictionary."""

    association_id = _public_ip_association_id(
        getattr(
            getattr(
                public_ip_address,
                "ip_configuration",
                None,
            ),
            "id",
            None,
        )
    )

    return {
        "name": public_ip_address.name,
        "location": public_ip_address.location,
        "resource_group": _resource_group_from_id(
            public_ip_address.id
        ),
        "ip_address": getattr(
            public_ip_address,
            "ip_address",
            None,
        ),
        "allocation_method": _string_or_none(
            getattr(
                public_ip_address,
                "public_ip_allocation_method",
                None,
            )
        ),
        "sku": getattr(
            getattr(public_ip_address, "sku", None),
            "name",
            None,
        ),
        "associated_resource_id": association_id,
        "associated_resource_type": (
            _associated_resource_type(association_id)
        ),
        "id": public_ip_address.id,
    }


def _serialize_network_interface(network_interface):
    """Convert an Azure network interface to a dictionary."""

    ip_configurations = getattr(
        network_interface,
        "ip_configurations",
        None,
    ) or []

    public_ip_address_ids = [
        public_ip_id
        for configuration in ip_configurations
        if (
            public_ip_id := getattr(
                getattr(
                    configuration,
                    "public_ip_address",
                    None,
                ),
                "id",
                None,
            )
        )
    ]

    private_ip_addresses = [
        private_ip_address
        for configuration in ip_configurations
        if (
            private_ip_address := getattr(
                configuration,
                "private_ip_address",
                None,
            )
        )
    ]

    network_security_group_id = getattr(
        getattr(
            network_interface,
            "network_security_group",
            None,
        ),
        "id",
        None,
    )

    return {
        "name": network_interface.name,
        "location": network_interface.location,
        "resource_group": _resource_group_from_id(
            network_interface.id
        ),
        "network_security_group_id": (
            network_security_group_id
        ),
        "public_ip_address_id": (
            public_ip_address_ids[0]
            if public_ip_address_ids
            else None
        ),
        "public_ip_address_ids": public_ip_address_ids,
        "private_ip_addresses": private_ip_addresses,
        "id": network_interface.id,
    }


def _reference_ids(references):
    """Extract Azure resource IDs from reference objects."""

    if not references:
        return []

    return [
        reference_id
        for reference in references
        if (
            reference_id := getattr(
                reference,
                "id",
                None,
            )
        )
    ]


def _public_ip_association_id(ip_configuration_id):
    """Return the parent resource ID for a public IP association."""

    if not ip_configuration_id:
        return None

    resource_id = str(ip_configuration_id)
    lower_resource_id = resource_id.lower()

    markers = (
        "/ipconfigurations/",
        "/frontendipconfigurations/",
    )

    for marker in markers:
        marker_index = lower_resource_id.find(marker)

        if marker_index >= 0:
            return resource_id[:marker_index]

    return resource_id


def _associated_resource_type(resource_id):
    """Determine the Azure resource type associated with a public IP."""

    if not resource_id:
        return None

    normalized_resource_id = str(resource_id).lower()

    if "/networkinterfaces/" in normalized_resource_id:
        return "NETWORK_INTERFACE"

    if "/loadbalancers/" in normalized_resource_id:
        return "LOAD_BALANCER"

    if "/applicationgateways/" in normalized_resource_id:
        return "APPLICATION_GATEWAY"

    return "UNKNOWN"


def _string_or_none(value):
    """Convert an Azure enum-like value to a string."""

    if value is None:
        return None

    return str(value)


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
