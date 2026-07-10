import azure_storage_exposure


def test_secure_storage_account_has_no_findings():
    result = azure_storage_exposure.analyze_storage_exposure(
        [
            {
                "name": "securestorage",
                "id": "/subscriptions/sub/storage/securestorage",
                "https_only": True,
                "minimum_tls_version": "TLS1_2",
                "allow_shared_key_access": False,
                "public_network_access": "Enabled",
                "network_default_action": "Deny",
            }
        ]
    )

    assert result["findings"] == []
    assert result["summary"]["findings"] == 0
    assert result["summary"]["exposed_accounts"] == 0


def test_exposed_storage_account_generates_findings():
    result = azure_storage_exposure.analyze_storage_exposure(
        [
            {
                "name": "publicstorage",
                "id": "/subscriptions/sub/storage/publicstorage",
                "https_only": False,
                "minimum_tls_version": "TLS1_0",
                "allow_shared_key_access": True,
                "public_network_access": "Enabled",
                "network_default_action": "Allow",
            }
        ]
    )

    controls = {
        finding["control"]
        for finding in result["findings"]
    }

    assert controls == {
        "Public Network Exposure",
        "Secure Transfer Required",
        "Minimum TLS Version",
        "Shared Key Authorization",
    }

    assert result["summary"] == {
        "storage_accounts": 1,
        "findings": 4,
        "exposed_accounts": 1,
        "critical": 0,
        "high": 2,
        "medium": 2,
        "low": 0,
    }


def test_missing_security_values_are_flagged():
    result = azure_storage_exposure.analyze_storage_exposure(
        [
            {
                "name": "unknownstorage",
                "id": "/subscriptions/sub/storage/unknownstorage",
            }
        ]
    )

    controls = {
        finding["control"]
        for finding in result["findings"]
    }

    assert "Secure Transfer Required" in controls
    assert "Minimum TLS Version" in controls
    assert "Shared Key Authorization" in controls


def test_empty_storage_list_returns_empty_summary():
    result = azure_storage_exposure.analyze_storage_exposure([])

    assert result["findings"] == []
    assert result["summary"]["storage_accounts"] == 0
    assert result["summary"]["findings"] == 0
