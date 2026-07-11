"""Safe Azure demo data for DGS Sentinel AI public demonstrations."""

from azure_network_exposure import (
    analyze_azure_network_exposure,
)
from azure_storage_exposure import analyze_storage_exposure


DEMO_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000"
DEMO_CLIENT_NAME = "Demo Azure Enterprise"

DEMO_PRODUCTION_RESOURCE_GROUP = "demo-production-rg"
DEMO_SHARED_RESOURCE_GROUP = "demo-shared-services-rg"


def build_azure_demo_dataset():
    """Return fresh Azure discovery and exposure demo results."""

    discovery = _build_demo_discovery()

    network_exposure = analyze_azure_network_exposure(
        network_security_groups=discovery[
            "network_security_groups"
        ],
        public_ip_addresses=discovery[
            "public_ip_addresses"
        ],
        network_interfaces=discovery[
            "network_interfaces"
        ],
        virtual_machines=discovery[
            "virtual_machines"
        ],
    )

    storage_exposure = analyze_storage_exposure(
        discovery["storage_accounts"]
    )

    return {
        "client_name": DEMO_CLIENT_NAME,
        "discovery": discovery,
        "network_exposure": network_exposure,
        "storage_exposure": storage_exposure,
    }


def _build_demo_discovery():
    """Build sanitized Azure resources for dashboard demonstrations."""

    linux_vm_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Compute",
        "virtualMachines",
        "demo-linux-web-01",
    )
    windows_vm_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Compute",
        "virtualMachines",
        "demo-windows-admin-01",
    )
    private_vm_id = _resource_id(
        DEMO_SHARED_RESOURCE_GROUP,
        "Microsoft.Compute",
        "virtualMachines",
        "demo-private-app-01",
    )

    linux_nic_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkInterfaces",
        "demo-linux-web-nic",
    )
    windows_nic_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkInterfaces",
        "demo-windows-admin-nic",
    )
    private_nic_id = _resource_id(
        DEMO_SHARED_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkInterfaces",
        "demo-private-app-nic",
    )

    linux_nsg_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkSecurityGroups",
        "demo-linux-web-nsg",
    )
    windows_nsg_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkSecurityGroups",
        "demo-windows-admin-nsg",
    )
    private_nsg_id = _resource_id(
        DEMO_SHARED_RESOURCE_GROUP,
        "Microsoft.Network",
        "networkSecurityGroups",
        "demo-private-app-nsg",
    )

    linux_public_ip_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "publicIPAddresses",
        "demo-linux-web-pip",
    )
    windows_public_ip_id = _resource_id(
        DEMO_PRODUCTION_RESOURCE_GROUP,
        "Microsoft.Network",
        "publicIPAddresses",
        "demo-windows-admin-pip",
    )
    unused_public_ip_id = _resource_id(
        DEMO_SHARED_RESOURCE_GROUP,
        "Microsoft.Network",
        "publicIPAddresses",
        "demo-unused-pip",
    )

    resource_groups = [
        {
            "name": DEMO_PRODUCTION_RESOURCE_GROUP,
            "location": "eastus",
            "id": _resource_group_id(
                DEMO_PRODUCTION_RESOURCE_GROUP
            ),
        },
        {
            "name": DEMO_SHARED_RESOURCE_GROUP,
            "location": "centralus",
            "id": _resource_group_id(
                DEMO_SHARED_RESOURCE_GROUP
            ),
        },
    ]

    virtual_machines = [
        {
            "name": "demo-linux-web-01",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "vm_size": "Standard_B2s",
            "network_interface_ids": [linux_nic_id],
            "id": linux_vm_id,
        },
        {
            "name": "demo-windows-admin-01",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "vm_size": "Standard_D2s_v5",
            "network_interface_ids": [windows_nic_id],
            "id": windows_vm_id,
        },
        {
            "name": "demo-private-app-01",
            "location": "centralus",
            "resource_group": DEMO_SHARED_RESOURCE_GROUP,
            "vm_size": "Standard_B2s",
            "network_interface_ids": [private_nic_id],
            "id": private_vm_id,
        },
    ]

    storage_accounts = [
        {
            "name": "demopublicstorage",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "kind": "StorageV2",
            "sku": "Standard_LRS",
            "https_only": False,
            "minimum_tls_version": "TLS1_0",
            "allow_shared_key_access": True,
            "public_network_access": "Enabled",
            "network_default_action": "Allow",
            "network_bypass": "AzureServices",
            "id": _resource_id(
                DEMO_PRODUCTION_RESOURCE_GROUP,
                "Microsoft.Storage",
                "storageAccounts",
                "demopublicstorage",
            ),
        },
        {
            "name": "demosecurestorage",
            "location": "centralus",
            "resource_group": DEMO_SHARED_RESOURCE_GROUP,
            "kind": "StorageV2",
            "sku": "Standard_GRS",
            "https_only": True,
            "minimum_tls_version": "TLS1_2",
            "allow_shared_key_access": False,
            "public_network_access": "Enabled",
            "network_default_action": "Deny",
            "network_bypass": "AzureServices",
            "id": _resource_id(
                DEMO_SHARED_RESOURCE_GROUP,
                "Microsoft.Storage",
                "storageAccounts",
                "demosecurestorage",
            ),
        },
    ]

    network_security_groups = [
        {
            "name": "demo-linux-web-nsg",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "security_rules": [
                {
                    "name": "Allow-SSH-From-Internet",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 100,
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "source_address_prefixes": None,
                    "destination_port_range": "22",
                    "destination_port_ranges": None,
                }
            ],
            "id": linux_nsg_id,
        },
        {
            "name": "demo-windows-admin-nsg",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "security_rules": [
                {
                    "name": "Allow-RDP-From-Internet",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 110,
                    "protocol": "Tcp",
                    "source_address_prefix": "0.0.0.0/0",
                    "source_address_prefixes": None,
                    "destination_port_range": "3389",
                    "destination_port_ranges": None,
                }
            ],
            "id": windows_nsg_id,
        },
        {
            "name": "demo-private-app-nsg",
            "location": "centralus",
            "resource_group": DEMO_SHARED_RESOURCE_GROUP,
            "security_rules": [
                {
                    "name": "Allow-HTTPS-From-Private-Network",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 100,
                    "protocol": "Tcp",
                    "source_address_prefix": "10.0.0.0/8",
                    "source_address_prefixes": None,
                    "destination_port_range": "443",
                    "destination_port_ranges": None,
                }
            ],
            "id": private_nsg_id,
        },
    ]

    public_ip_addresses = [
        {
            "name": "demo-linux-web-pip",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "ip_address": "203.0.113.10",
            "allocation_method": "Static",
            "sku": "Standard",
            "associated_resource_id": linux_nic_id,
            "associated_resource_type": "NETWORK_INTERFACE",
            "id": linux_public_ip_id,
        },
        {
            "name": "demo-windows-admin-pip",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "ip_address": "198.51.100.25",
            "allocation_method": "Static",
            "sku": "Standard",
            "associated_resource_id": windows_nic_id,
            "associated_resource_type": "NETWORK_INTERFACE",
            "id": windows_public_ip_id,
        },
        {
            "name": "demo-unused-pip",
            "location": "centralus",
            "resource_group": DEMO_SHARED_RESOURCE_GROUP,
            "ip_address": "192.0.2.45",
            "allocation_method": "Static",
            "sku": "Standard",
            "associated_resource_id": None,
            "associated_resource_type": None,
            "id": unused_public_ip_id,
        },
    ]

    network_interfaces = [
        {
            "name": "demo-linux-web-nic",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "network_security_group_id": linux_nsg_id,
            "public_ip_address_id": linux_public_ip_id,
            "public_ip_address_ids": [linux_public_ip_id],
            "private_ip_addresses": ["10.10.1.10"],
            "id": linux_nic_id,
        },
        {
            "name": "demo-windows-admin-nic",
            "location": "eastus",
            "resource_group": DEMO_PRODUCTION_RESOURCE_GROUP,
            "network_security_group_id": windows_nsg_id,
            "public_ip_address_id": windows_public_ip_id,
            "public_ip_address_ids": [windows_public_ip_id],
            "private_ip_addresses": ["10.10.1.20"],
            "id": windows_nic_id,
        },
        {
            "name": "demo-private-app-nic",
            "location": "centralus",
            "resource_group": DEMO_SHARED_RESOURCE_GROUP,
            "network_security_group_id": private_nsg_id,
            "public_ip_address_id": None,
            "public_ip_address_ids": [],
            "private_ip_addresses": ["10.20.1.10"],
            "id": private_nic_id,
        },
    ]

    return {
        "subscription_id": DEMO_SUBSCRIPTION_ID,
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
            "public_ip_addresses": len(public_ip_addresses),
            "network_interfaces": len(network_interfaces),
        },
    }


def _resource_group_id(resource_group):
    """Build a sanitized Azure demo resource-group ID."""

    return (
        f"/subscriptions/{DEMO_SUBSCRIPTION_ID}"
        f"/resourceGroups/{resource_group}"
    )


def _resource_id(
    resource_group,
    provider,
    resource_type,
    resource_name,
):
    """Build a sanitized Azure demo resource ID."""

    return (
        f"{_resource_group_id(resource_group)}"
        f"/providers/{provider}"
        f"/{resource_type}/{resource_name}"
    )
