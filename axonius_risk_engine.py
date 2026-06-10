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


def generate_caasm_policy_findings(assets, identities):
    findings = []

    for asset in assets:
        asset_id = asset.get("asset_id", "Unknown Asset")
        hostname = asset.get("hostname", asset_id)
        risk_score = asset.get("risk_score", 0)

        if not asset.get("managed", False):
            findings.append({
                "Category": "Asset Coverage",
                "Finding": "Unmanaged Asset",
                "Resource": hostname,
                "Priority": "HIGH",
                "Risk Score": max(risk_score, 75),
                "Recommendation": (
                    "Validate ownership, identify missing security-tool coverage, "
                    "and enroll the asset in approved management controls."
                )
            })

        if risk_score >= 80:
            findings.append({
                "Category": "Asset Risk",
                "Finding": "High-Risk Asset",
                "Resource": hostname,
                "Priority": "CRITICAL",
                "Risk Score": risk_score,
                "Recommendation": (
                    "Perform immediate asset review, validate exposure, "
                    "and create a remediation plan."
                )
            })

    for identity in identities:
        username = identity.get("username", "Unknown Identity")
        risk_score = identity.get("risk_score", 0)

        if identity.get("orphaned", False):
            findings.append({
                "Category": "Identity Governance",
                "Finding": "Orphaned Account",
                "Resource": username,
                "Priority": "CRITICAL",
                "Risk Score": max(risk_score, 90),
                "Recommendation": (
                    "Validate account ownership and business need. "
                    "Disable or remove the account if ownership cannot be confirmed."
                )
            })

        if (
            identity.get("privileged", False)
            and not identity.get("mfa_enabled", False)
        ):
            findings.append({
                "Category": "Privileged Access",
                "Finding": "Privileged Account Without MFA",
                "Resource": username,
                "Priority": "CRITICAL",
                "Risk Score": max(risk_score, 90),
                "Recommendation": (
                    "Enable MFA immediately and review privileged access "
                    "for least-privilege alignment."
                )
            })

        elif not identity.get("mfa_enabled", False):
            findings.append({
                "Category": "Identity Security",
                "Finding": "Account Without MFA",
                "Resource": username,
                "Priority": "HIGH",
                "Risk Score": max(risk_score, 70),
                "Recommendation": (
                    "Enable MFA and validate authentication policy compliance."
                )
            })

    return sorted(
        findings,
        key=lambda item: item.get("Risk Score", 0),
        reverse=True
    )
