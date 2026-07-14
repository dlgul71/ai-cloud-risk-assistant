import pytest

import azure_client_accounts


def test_create_azure_credential_requires_all_values():
    with pytest.raises(
        ValueError,
        match="tenant ID, client ID, and client secret",
    ):
        azure_client_accounts.create_azure_credential(
            tenant_id="",
            client_id="client-id",
            client_secret="client-secret",  # pragma: allowlist secret
        )


def test_create_azure_credential_uses_service_principal(
    monkeypatch,
):
    captured = {}

    class FakeCredential:
        def __init__(
            self,
            tenant_id,
            client_id,
            client_secret,
        ):
            captured["tenant_id"] = tenant_id
            captured["client_id"] = client_id
            captured["client_secret"] = client_secret

    monkeypatch.setattr(
        azure_client_accounts,
        "ClientSecretCredential",
        FakeCredential,
    )

    credential = (
        azure_client_accounts.create_azure_credential(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",  # pragma: allowlist secret
        )
    )

    assert isinstance(credential, FakeCredential)
    assert captured == {
        "tenant_id": "tenant-id",
        "client_id": "client-id",
        "client_secret": "client-secret",  # pragma: allowlist secret
    }


def test_test_azure_subscription_returns_identity(
    monkeypatch,
):
    class FakeSubscription:
        subscription_id = "subscription-id"
        display_name = "DGS Azure Subscription"
        state = "Enabled"

    class FakeSubscriptions:
        def get(self, subscription_id):
            assert subscription_id == "subscription-id"
            return FakeSubscription()

    class FakeSubscriptionClient:
        def __init__(self, credential):
            assert credential == "credential"
            self.subscriptions = FakeSubscriptions()

    monkeypatch.setattr(
        azure_client_accounts,
        "create_azure_credential",
        lambda **kwargs: "credential",
    )
    monkeypatch.setattr(
        azure_client_accounts,
        "SubscriptionClient",
        FakeSubscriptionClient,
    )

    result = (
        azure_client_accounts.test_azure_subscription(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",  # pragma: allowlist secret
            subscription_id="subscription-id",
        )
    )

    assert result == {
        "subscription_id": "subscription-id",
        "display_name": "DGS Azure Subscription",
        "state": "Enabled",
    }


def test_test_azure_subscription_requires_subscription_id():
    with pytest.raises(
        ValueError,
        match="subscription ID",
    ):
        azure_client_accounts.test_azure_subscription(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",  # pragma: allowlist secret
            subscription_id="",
        )
