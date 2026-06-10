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


def calculate_identity_governance_metrics(identities):
    total_identities = len(identities)

    privileged_accounts = len([
        identity for identity in identities
        if identity.get("privileged", False)
    ])

    orphaned_accounts = len([
        identity for identity in identities
        if identity.get("orphaned", False)
    ])

    mfa_exceptions = len([
        identity for identity in identities
        if not identity.get("mfa_enabled", False)
    ])

    privileged_without_mfa = len([
        identity for identity in identities
        if identity.get("privileged", False)
        and not identity.get("mfa_enabled", False)
    ])

    high_risk_identities = len([
        identity for identity in identities
        if identity.get("risk_score", 0) >= 75
    ])

    compliant_identities = len([
        identity for identity in identities
        if identity.get("mfa_enabled", False)
        and not identity.get("orphaned", False)
    ])

    identity_compliance_rate = round(
        (compliant_identities / total_identities) * 100,
        2
    ) if total_identities else 0

    return {
        "Total Identities": total_identities,
        "Privileged Accounts": privileged_accounts,
        "Orphaned Accounts": orphaned_accounts,
        "MFA Exceptions": mfa_exceptions,
        "Privileged Without MFA": privileged_without_mfa,
        "High-Risk Identities": high_risk_identities,
        "Identity Compliance Rate %": identity_compliance_rate
    }


def generate_identity_governance_rows(identities):
    rows = []

    for identity in identities:
        username = identity.get("username", "Unknown Identity")
        privileged = identity.get("privileged", False)
        mfa_enabled = identity.get("mfa_enabled", False)
        orphaned = identity.get("orphaned", False)
        risk_score = identity.get("risk_score", 0)

        exceptions = []

        if orphaned:
            exceptions.append("Orphaned Account")

        if privileged and not mfa_enabled:
            exceptions.append("Privileged Account Without MFA")

        elif not mfa_enabled:
            exceptions.append("MFA Not Enabled")

        if risk_score >= 75:
            exceptions.append("High-Risk Identity")

        rows.append({
            "Username": username,
            "Identity Type": identity.get("identity_type", "Unknown"),
            "Privileged": privileged,
            "MFA Enabled": mfa_enabled,
            "Orphaned": orphaned,
            "Risk Score": risk_score,
            "Governance Exceptions": ", ".join(exceptions) if exceptions else "None"
        })

    return sorted(
        rows,
        key=lambda item: item.get("Risk Score", 0),
        reverse=True
    )


def calculate_coverage_gap_metrics(coverage_sources):
    total_sources = len(coverage_sources)

    connected_sources = len([
        source for source in coverage_sources
        if source.get("connected", False)
    ])

    disconnected_sources = total_sources - connected_sources

    avg_coverage = round(
        sum(
            source.get("coverage_percent", 0)
            for source in coverage_sources
        ) / total_sources,
        2
    ) if total_sources else 0

    critical_gaps = len([
        source for source in coverage_sources
        if source.get("coverage_percent", 0) < 50
    ])

    return {
        "Total Sources": total_sources,
        "Connected Sources": connected_sources,
        "Disconnected Sources": disconnected_sources,
        "Average Coverage %": avg_coverage,
        "Critical Coverage Gaps": critical_gaps
    }


def generate_coverage_gap_findings(coverage_sources):
    findings = []

    for source in coverage_sources:
        coverage = source.get("coverage_percent", 0)
        connected = source.get("connected", False)

        if not connected:
            priority = "CRITICAL"
            recommendation = (
                "Establish connector integration and validate asset ingestion."
            )

        elif coverage < 75:
            priority = "HIGH"
            recommendation = (
                "Investigate visibility gaps and reconcile missing assets."
            )

        else:
            priority = "STANDARD"
            recommendation = (
                "Monitor connector health and validate coverage regularly."
            )

        findings.append({
            "Source": source.get("source"),
            "Category": source.get("category"),
            "Connected": connected,
            "Assets Discovered": source.get("assets_discovered", 0),
            "Coverage %": coverage,
            "Priority": priority,
            "Recommendation": recommendation
        })

    return sorted(
        findings,
        key=lambda item: item.get("Coverage %", 0)
    )
