from cloud_scan_routing import (
    build_azure_snapshot_assets,
    normalize_cloud_provider,
    summarize_azure_resources,
)


def test_normalize_cloud_provider():
    assert normalize_cloud_provider("azure") == "AZURE"
    assert normalize_cloud_provider(" AWS ") == "AWS"
    assert normalize_cloud_provider(None) == "AWS"
    assert normalize_cloud_provider("unknown") == "AWS"


def test_summarize_azure_resources():
    discovery = {
        "virtual_machines": [{"name": "vm-1"}],
        "storage_accounts": [
            {"name": "storage-1"},
            {"name": "storage-2"},
        ],
        "network_security_groups": [],
        "public_ip_addresses": [{"name": "pip-1"}],
        "network_interfaces": [{"name": "nic-1"}],
    }

    assert summarize_azure_resources(discovery) == {
        "virtual_machines": 1,
        "storage_accounts": 2,
        "network_security_groups": 0,
        "public_ip_addresses": 1,
        "network_interfaces": 1,
    }


def test_build_azure_snapshot_assets():
    discovery = {
        "virtual_machines": [
            {
                "id": "/subscriptions/sub-1/vm-1",
                "name": "vm-1",
                "location": "centralus",
                "power_state": "running",
            }
        ],
        "public_ip_addresses": [
            {
                "id": "/subscriptions/sub-1/pip-1",
                "name": "pip-1",
                "location": "centralus",
                "ip_address": "203.0.113.10",
            }
        ],
    }

    assets = build_azure_snapshot_assets(
        discovery,
        subscription_id="sub-1",
        scanned_at="2026-07-12T02:00:00+00:00",
    )

    assert len(assets) == 2
    assert assets[0]["asset_type"] == "Azure Virtual Machine"
    assert assets[0]["account_id"] == "sub-1"
    assert assets[1]["asset_type"] == "Azure Public IP Address"
    assert assets[1]["public_ip"] == "203.0.113.10"


def test_build_azure_snapshot_assets_handles_missing_data():
    assert build_azure_snapshot_assets(
        None,
        subscription_id="sub-1",
    ) == []
