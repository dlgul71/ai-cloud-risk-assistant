def calculate_caasm_metrics(assets, identities):
    total_assets = len(assets)
    managed_assets = len([
        asset for asset in assets
        if asset.get("managed")
    ])

    unmanaged_assets = total_assets - managed_assets

    total_identities = len(identities)

    privileged_users = len([
        identity for identity in identities
        if identity.get("privileged")
    ])

    orphaned_accounts = len([
        identity for identity in identities
        if identity.get("orphaned")
    ])

    mfa_enabled = len([
        identity for identity in identities
        if identity.get("mfa_enabled")
    ])

    asset_coverage = round(
        (managed_assets / total_assets) * 100,
        2
    ) if total_assets else 0

    mfa_coverage = round(
        (mfa_enabled / total_identities) * 100,
        2
    ) if total_identities else 0

    identity_risk_penalty = (
        orphaned_accounts * 15
        + privileged_users * 5
        + unmanaged_assets * 10
    )

    caasm_score = max(
        0,
        min(
            100,
            round(
                (asset_coverage * 0.55)
                + (mfa_coverage * 0.45)
                - identity_risk_penalty,
                2
            )
        )
    )

    return {
        "Total Assets": total_assets,
        "Managed Assets": managed_assets,
        "Unmanaged Assets": unmanaged_assets,
        "Asset Coverage %": asset_coverage,
        "Total Identities": total_identities,
        "Privileged Users": privileged_users,
        "Orphaned Accounts": orphaned_accounts,
        "MFA Coverage %": mfa_coverage,
        "CAASM Score": caasm_score
    }
