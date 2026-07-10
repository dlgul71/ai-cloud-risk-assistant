import azure_resource_discovery


def test_resource_group_from_id():
    resource_id = (
        "/subscriptions/subscription-id/"
        "resourceGroups/DGS-Production/"
        "providers/Microsoft.Compute/"
        "virtualMachines/web-01"
    )

    assert (
        azure_resource_discovery._resource_group_from_id(resource_id)
        == "DGS-Production"
    )


def test_discover_azure_resources(monkeypatch):
    class FakeResourceGroup:
        name = "DGS-Production"
        location = "eastus"
        id = "/subscriptions/sub/resourceGroups/DGS-Production"

    class FakeVMProfile:
        vm_size = "Standard_B2s"

    class FakeVM:
        name = "web-01"
        location = "eastus"
        hardware_profile = FakeVMProfile()
        id = (
            "/subscriptions/sub/resourceGroups/DGS-Production/"
            "providers/Microsoft.Compute/virtualMachines/web-01"
        )

    class FakeSku:
        name = "Standard_LRS"

    class FakeNetworkRuleSet:
        default_action = "Deny"
        bypass = "AzureServices"

    class FakeStorage:
        name = "dgsstorage"
        location = "eastus"
        kind = "StorageV2"
        sku = FakeSku()
        enable_https_traffic_only = True
        minimum_tls_version = "TLS1_2"
        allow_shared_key_access = False
        public_network_access = "Enabled"
        network_rule_set = FakeNetworkRuleSet()
        id = (
            "/subscriptions/sub/resourceGroups/DGS-Production/"
            "providers/Microsoft.Storage/storageAccounts/dgsstorage"
        )

    class FakeResourceGroups:
        def list(self):
            return [FakeResourceGroup()]

    class FakeVirtualMachines:
        def list_all(self):
            return [FakeVM()]

    class FakeStorageAccounts:
        def list(self):
            return [FakeStorage()]

    class FakeResourceClient:
        def __init__(self, credential, subscription_id):
            self.resource_groups = FakeResourceGroups()

    class FakeComputeClient:
        def __init__(self, credential, subscription_id):
            self.virtual_machines = FakeVirtualMachines()

    class FakeStorageClient:
        def __init__(self, credential, subscription_id):
            self.storage_accounts = FakeStorageAccounts()

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

    result = azure_resource_discovery.discover_azure_resources(
        credential="credential",
        subscription_id="subscription-id",
    )

    assert result["summary"] == {
        "resource_groups": 1,
        "virtual_machines": 1,
        "storage_accounts": 1,
    }
    assert result["virtual_machines"][0]["resource_group"] == (
        "DGS-Production"
    )
    storage = result["storage_accounts"][0]

    assert storage["https_only"] is True
    assert storage["minimum_tls_version"] == "TLS1_2"
    assert storage["allow_shared_key_access"] is False
    assert storage["network_default_action"] == "Deny"
    assert storage["network_bypass"] == "AzureServices"


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
