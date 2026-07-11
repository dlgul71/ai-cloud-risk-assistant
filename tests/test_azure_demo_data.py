from azure_demo_data import build_azure_demo_dataset


def test_builds_complete_azure_demo_dataset():
    result = build_azure_demo_dataset()

    assert set(result) == {
        "client_name",
        "discovery",
        "network_exposure",
        "storage_exposure",
    }

    assert result["client_name"] == "Demo Azure Enterprise"


def test_demo_discovery_contains_expected_resources():
    discovery = build_azure_demo_dataset()["discovery"]

    assert discovery["summary"] == {
        "resource_groups": 2,
        "virtual_machines": 3,
        "storage_accounts": 2,
        "network_security_groups": 3,
        "public_ip_addresses": 3,
        "network_interfaces": 3,
    }

    assert {
        virtual_machine["name"]
        for virtual_machine in discovery["virtual_machines"]
    } == {
        "demo-linux-web-01",
        "demo-windows-admin-01",
        "demo-private-app-01",
    }

    assert {
        storage_account["name"]
        for storage_account in discovery["storage_accounts"]
    } == {
        "demopublicstorage",
        "demosecurestorage",
    }


def test_demo_network_exposure_contains_realistic_findings():
    network_exposure = build_azure_demo_dataset()[
        "network_exposure"
    ]

    assert network_exposure["summary"] == {
        "network_security_groups": 3,
        "exposed_network_security_groups": 2,
        "public_ip_addresses": 3,
        "assigned_public_ip_addresses": 2,
        "unassigned_public_ip_addresses": 1,
        "virtual_machines": 3,
        "internet_facing_virtual_machines": 2,
        "critical_findings": 4,
        "high_findings": 2,
        "medium_findings": 1,
        "total_findings": 7,
    }

    exposure_types = {
        finding["exposure_type"]
        for finding in network_exposure["findings"]
    }

    assert "MANAGEMENT_PORT_EXPOSED" in exposure_types
    assert "ASSIGNED_PUBLIC_IP" in exposure_types
    assert "UNASSIGNED_PUBLIC_IP" in exposure_types
    assert "VM_MANAGEMENT_PORT_EXPOSED" in exposure_types


def test_demo_storage_exposure_contains_secure_and_exposed_accounts():
    storage_exposure = build_azure_demo_dataset()[
        "storage_exposure"
    ]

    assert storage_exposure["summary"] == {
        "storage_accounts": 2,
        "findings": 4,
        "exposed_accounts": 1,
        "critical": 0,
        "high": 2,
        "medium": 2,
        "low": 0,
    }

    controls = {
        finding["control"]
        for finding in storage_exposure["findings"]
    }

    assert controls == {
        "Public Network Exposure",
        "Secure Transfer Required",
        "Minimum TLS Version",
        "Shared Key Authorization",
    }


def test_demo_builder_returns_fresh_data():
    first_result = build_azure_demo_dataset()
    first_result["discovery"]["virtual_machines"].clear()

    second_result = build_azure_demo_dataset()

    assert len(
        second_result["discovery"]["virtual_machines"]
    ) == 3
