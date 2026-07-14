from types import SimpleNamespace

import azure_resource_discovery


RESOURCE_GROUP = "DGS-Production"

VM_ID = (
    "/subscriptions/sub/resourceGroups/DGS-Production/"
    "providers/Microsoft.Compute/virtualMachines/web-01"
)
NIC_ID = (
    "/subscriptions/sub/resourceGroups/DGS-Production/"
    "providers/Microsoft.Network/networkInterfaces/web-nic"
)
NSG_ID = (
    "/subscriptions/sub/resourceGroups/DGS-Production/"
    "providers/Microsoft.Network/networkSecurityGroups/web-nsg"
)
PUBLIC_IP_ID = (
    "/subscriptions/sub/resourceGroups/DGS-Production/"
    "providers/Microsoft.Network/publicIPAddresses/web-public-ip"
)


def test_resource_group_from_id():
    assert (
        azure_resource_discovery._resource_group_from_id(VM_ID)
        == RESOURCE_GROUP
    )


def test_discover_azure_resources(monkeypatch):
    class FakeResourceGroup:
        name = RESOURCE_GROUP
        location = "eastus"
        id = (
            "/subscriptions/sub/resourceGroups/DGS-Production"
        )

    class FakeVM:
        name = "web-01"
        location = "eastus"
        hardware_profile = SimpleNamespace(
            vm_size="Standard_B2s"
        )
        network_profile = SimpleNamespace(
            network_interfaces=[
                SimpleNamespace(id=NIC_ID),
            ]
        )
        id = VM_ID

    class FakeStorage:
        name = "dgsstorage"
        location = "eastus"
        kind = "StorageV2"
        sku = SimpleNamespace(name="Standard_LRS")
        enable_https_traffic_only = True
        minimum_tls_version = "TLS1_2"
        allow_shared_key_access = False
        public_network_access = "Enabled"
        network_rule_set = SimpleNamespace(
            default_action="Deny",
            bypass="AzureServices",
        )
        id = (
            "/subscriptions/sub/resourceGroups/DGS-Production/"
            "providers/Microsoft.Storage/"
            "storageAccounts/dgsstorage"
        )

    class FakeSecurityRule:
        name = "Allow-SSH"
        access = "Allow"
        direction = "Inbound"
        priority = 100
        protocol = "Tcp"
        source_address_prefix = "Internet"
        source_address_prefixes = None
        destination_port_range = "22"
        destination_port_ranges = None

    class FakeNetworkSecurityGroup:
        name = "web-nsg"
        location = "eastus"
        id = NSG_ID
        security_rules = [FakeSecurityRule()]

    class FakePublicIPAddress:
        name = "web-public-ip"
        location = "eastus"
        id = PUBLIC_IP_ID
        ip_address = "203.0.113.10"
        public_ip_allocation_method = "Static"
        sku = SimpleNamespace(name="Standard")
        ip_configuration = SimpleNamespace(
            id=f"{NIC_ID}/ipConfigurations/ipconfig1"
        )

    class FakeIPConfiguration:
        private_ip_address = "10.0.0.4"
        public_ip_address = SimpleNamespace(
            id=PUBLIC_IP_ID
        )

    class FakeNetworkInterface:
        name = "web-nic"
        location = "eastus"
        id = NIC_ID
        network_security_group = SimpleNamespace(
            id=NSG_ID
        )
        ip_configurations = [FakeIPConfiguration()]

    class FakeResourceGroups:
        def list(self):
            return [FakeResourceGroup()]

    class FakeVirtualMachines:
        def list_all(self):
            return [FakeVM()]

    class FakeStorageAccounts:
        def list(self):
            return [FakeStorage()]

    class FakeNetworkSecurityGroups:
        def list_all(self):
            return [FakeNetworkSecurityGroup()]

    class FakePublicIPAddresses:
        def list_all(self):
            return [FakePublicIPAddress()]

    class FakeNetworkInterfaces:
        def list_all(self):
            return [FakeNetworkInterface()]

    class FakeResourceClient:
        def __init__(self, credential, subscription_id):
            self.resource_groups = FakeResourceGroups()

    class FakeComputeClient:
        def __init__(self, credential, subscription_id):
            self.virtual_machines = FakeVirtualMachines()

    class FakeStorageClient:
        def __init__(self, credential, subscription_id):
            self.storage_accounts = FakeStorageAccounts()

    class FakeNetworkClient:
        def __init__(self, credential, subscription_id):
            self.network_security_groups = (
                FakeNetworkSecurityGroups()
            )
            self.public_ip_addresses = (
                FakePublicIPAddresses()
            )
            self.network_interfaces = FakeNetworkInterfaces()

    monkeypatch.setattr(
        azure_resource_discovery,
        "ResourceManagementClient",
        FakeResourceClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "ComputeManagementClient",
        FakeComputeClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "StorageManagementClient",
        FakeStorageClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "NetworkManagementClient",
        FakeNetworkClient,
        raising=False,
    )

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["summary"] == {
        "resource_groups": 1,
        "virtual_machines": 1,
        "storage_accounts": 1,
        "network_security_groups": 1,
        "public_ip_addresses": 1,
        "network_interfaces": 1,
    }

    virtual_machine = result["virtual_machines"][0]

    assert virtual_machine["resource_group"] == RESOURCE_GROUP
    assert virtual_machine["network_interface_ids"] == [
        NIC_ID
    ]

    storage = result["storage_accounts"][0]

    assert storage["https_only"] is True
    assert storage["minimum_tls_version"] == "TLS1_2"
    assert storage["allow_shared_key_access"] is False
    assert storage["network_default_action"] == "Deny"
    assert storage["network_bypass"] == "AzureServices"

    network_security_group = result[
        "network_security_groups"
    ][0]

    assert network_security_group["name"] == "web-nsg"
    assert network_security_group["resource_group"] == (
        RESOURCE_GROUP
    )
    assert network_security_group["security_rules"] == [
        {
            "name": "Allow-SSH",
            "access": "Allow",
            "direction": "Inbound",
            "priority": 100,
            "protocol": "Tcp",
            "source_address_prefix": "Internet",
            "source_address_prefixes": None,
            "destination_port_range": "22",
            "destination_port_ranges": None,
        }
    ]

    public_ip = result["public_ip_addresses"][0]

    assert public_ip["ip_address"] == "203.0.113.10"
    assert public_ip["allocation_method"] == "Static"
    assert public_ip["sku"] == "Standard"
    assert public_ip["associated_resource_id"] == NIC_ID
    assert public_ip["associated_resource_type"] == (
        "NETWORK_INTERFACE"
    )

    network_interface = result["network_interfaces"][0]

    assert network_interface["network_security_group_id"] == (
        NSG_ID
    )
    assert network_interface["public_ip_address_id"] == (
        PUBLIC_IP_ID
    )
    assert network_interface["public_ip_address_ids"] == [
        PUBLIC_IP_ID
    ]
    assert network_interface["private_ip_addresses"] == [
        "10.0.0.4"
    ]


def test_discover_azure_resources_requires_subscription_id():
    try:
        azure_resource_discovery.discover_azure_resources(
            credential="credential",
            subscription_id="",
        )
    except ValueError as exc:
        assert "subscription ID" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


class _DiscoveryOperation:
    def __init__(self, values=None, error=None):
        self.values = list(values or [])
        self.error = error

    def _result(self):
        if self.error is not None:
            raise self.error

        return self.values

    def list(self):
        return self._result()

    def list_all(self):
        return self._result()


def _patch_discovery_clients(
    monkeypatch,
    *,
    resource_groups=None,
    virtual_machines=None,
    storage_accounts=None,
    network_security_groups=None,
    public_ip_addresses=None,
    network_interfaces=None,
    errors=None,
):
    errors = errors or {}

    class FakeResourceClient:
        def __init__(self, credential, subscription_id):
            self.resource_groups = _DiscoveryOperation(
                resource_groups,
                errors.get("resource_groups"),
            )

    class FakeComputeClient:
        def __init__(self, credential, subscription_id):
            self.virtual_machines = _DiscoveryOperation(
                virtual_machines,
                errors.get("virtual_machines"),
            )

    class FakeStorageClient:
        def __init__(self, credential, subscription_id):
            self.storage_accounts = _DiscoveryOperation(
                storage_accounts,
                errors.get("storage_accounts"),
            )

    class FakeNetworkClient:
        def __init__(self, credential, subscription_id):
            self.network_security_groups = _DiscoveryOperation(
                network_security_groups,
                errors.get("network_security_groups"),
            )
            self.public_ip_addresses = _DiscoveryOperation(
                public_ip_addresses,
                errors.get("public_ip_addresses"),
            )
            self.network_interfaces = _DiscoveryOperation(
                network_interfaces,
                errors.get("network_interfaces"),
            )

    monkeypatch.setattr(
        azure_resource_discovery,
        "ResourceManagementClient",
        FakeResourceClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "ComputeManagementClient",
        FakeComputeClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "StorageManagementClient",
        FakeStorageClient,
    )
    monkeypatch.setattr(
        azure_resource_discovery,
        "NetworkManagementClient",
        FakeNetworkClient,
    )


def test_storage_failure_returns_partial_discovery(monkeypatch):
    resource_group = SimpleNamespace(
        name=RESOURCE_GROUP,
        location="eastus",
        id=(
            "/subscriptions/sub/resourceGroups/"
            f"{RESOURCE_GROUP}"
        ),
    )
    virtual_machine = SimpleNamespace(
        name="web-01",
        location="eastus",
        hardware_profile=SimpleNamespace(
            vm_size="Standard_B2s"
        ),
        network_profile=SimpleNamespace(
            network_interfaces=[]
        ),
        id=VM_ID,
    )

    _patch_discovery_clients(
        monkeypatch,
        resource_groups=[resource_group],
        virtual_machines=[virtual_machine],
        errors={
            "storage_accounts": RuntimeError(
                "Storage service unavailable"
            )
        },
    )

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["discovery_status"] == "PARTIAL"
    assert result["resource_groups"][0]["name"] == (
        RESOURCE_GROUP
    )
    assert result["virtual_machines"][0]["name"] == "web-01"
    assert result["storage_accounts"] == []

    assert result["summary"] == {
        "resource_groups": 1,
        "virtual_machines": 1,
        "storage_accounts": 0,
        "network_security_groups": 0,
        "public_ip_addresses": 0,
        "network_interfaces": 0,
    }

    assert result["errors"] == [
        {
            "resource_type": "storage_accounts",
            "error_type": "RuntimeError",
            "message": "Storage service unavailable",
        }
    ]


def test_network_resource_failure_does_not_stop_other_network_calls(
    monkeypatch,
):
    public_ip = SimpleNamespace(
        name="web-public-ip",
        location="eastus",
        id=PUBLIC_IP_ID,
        ip_address="203.0.113.10",
        public_ip_allocation_method="Static",
        sku=SimpleNamespace(name="Standard"),
        ip_configuration=SimpleNamespace(
            id=f"{NIC_ID}/ipConfigurations/ipconfig1"
        ),
    )
    network_interface = SimpleNamespace(
        name="web-nic",
        location="eastus",
        id=NIC_ID,
        network_security_group=None,
        ip_configurations=[],
    )

    _patch_discovery_clients(
        monkeypatch,
        public_ip_addresses=[public_ip],
        network_interfaces=[network_interface],
        errors={
            "network_security_groups": RuntimeError(
                "NSG discovery unavailable"
            )
        },
    )

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["discovery_status"] == "PARTIAL"
    assert result["network_security_groups"] == []
    assert len(result["public_ip_addresses"]) == 1
    assert len(result["network_interfaces"]) == 1

    assert result["summary"]["network_security_groups"] == 0
    assert result["summary"]["public_ip_addresses"] == 1
    assert result["summary"]["network_interfaces"] == 1

    assert result["errors"] == [
        {
            "resource_type": "network_security_groups",
            "error_type": "RuntimeError",
            "message": "NSG discovery unavailable",
        }
    ]


def test_successful_discovery_reports_complete_status(
    monkeypatch,
):
    _patch_discovery_clients(monkeypatch)

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["discovery_status"] == "COMPLETE"
    assert result["errors"] == []


FIXED_SCAN_TIME = "2026-07-11T12:00:00+00:00"


def test_discovery_includes_scan_timestamps_and_service_status(
    monkeypatch,
):
    monkeypatch.setattr(
        azure_resource_discovery,
        "_utc_now_iso",
        lambda: FIXED_SCAN_TIME,
        raising=False,
    )

    _patch_discovery_clients(monkeypatch)

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["started_at"] == FIXED_SCAN_TIME
    assert result["completed_at"] == FIXED_SCAN_TIME

    assert result["service_status"] == {
        "resource_groups": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
        "virtual_machines": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
        "storage_accounts": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
        "network_security_groups": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
        "public_ip_addresses": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
        "network_interfaces": {
            "status": "COMPLETE",
            "resource_count": 0,
            "scanned_at": FIXED_SCAN_TIME,
            "error": None,
        },
    }


def test_failed_service_has_failed_status_and_timestamp(
    monkeypatch,
):
    monkeypatch.setattr(
        azure_resource_discovery,
        "_utc_now_iso",
        lambda: FIXED_SCAN_TIME,
        raising=False,
    )

    _patch_discovery_clients(
        monkeypatch,
        errors={
            "storage_accounts": RuntimeError(
                "Storage service unavailable"
            )
        },
    )

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    storage_status = result["service_status"][
        "storage_accounts"
    ]

    assert storage_status == {
        "status": "FAILED",
        "resource_count": 0,
        "scanned_at": FIXED_SCAN_TIME,
        "error": {
            "error_type": "RuntimeError",
            "message": "Storage service unavailable",
        },
    }

    assert result["service_status"]["virtual_machines"][
        "status"
    ] == "COMPLETE"
    assert result["discovery_status"] == "PARTIAL"
