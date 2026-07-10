"""Azure client authentication and subscription validation."""

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import SubscriptionClient
except ImportError:
    ClientSecretCredential = None
    SubscriptionClient = None


def create_azure_credential(
    tenant_id,
    client_id,
    client_secret,
):
    """Create an Azure service-principal credential."""

    if not all((tenant_id, client_id, client_secret)):
        raise ValueError(
            "Azure tenant ID, client ID, and client secret are required."
        )

    if ClientSecretCredential is None:
        raise RuntimeError(
            "Azure Identity SDK is not installed."
        )

    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def test_azure_subscription(
    tenant_id,
    client_id,
    client_secret,
    subscription_id,
):
    """Validate access to an Azure subscription."""

    if not subscription_id:
        raise ValueError(
            "Azure subscription ID is required."
        )

    credential = create_azure_credential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    if SubscriptionClient is None:
        raise RuntimeError(
            "Azure Resource Management SDK is not installed."
        )

    client = SubscriptionClient(credential)
    subscription = client.subscriptions.get(
        subscription_id
    )

    return {
        "subscription_id": subscription.subscription_id,
        "display_name": subscription.display_name,
        "state": str(subscription.state),
    }
