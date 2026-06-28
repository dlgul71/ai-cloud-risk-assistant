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


def generate_caasm_executive_recommendations(
    metrics,
    identity_governance_metrics,
    coverage_gap_metrics,
    policy_findings,
    coverage_gap_findings
):
    recommendations = []

    orphaned_accounts = identity_governance_metrics.get(
        "Orphaned Accounts",
        0
    )

    privileged_without_mfa = identity_governance_metrics.get(
        "Privileged Without MFA",
        0
    )

    unmanaged_assets = metrics.get(
        "Unmanaged Assets",
        0
    )

    critical_coverage_gaps = coverage_gap_metrics.get(
        "Critical Coverage Gaps",
        0
    )

    caasm_score = metrics.get(
        "CAASM Score",
        0
    )

    if orphaned_accounts > 0:
        recommendations.append({
            "Priority": "CRITICAL",
            "Category": "Identity Governance",
            "Recommendation": (
                f"Investigate and remediate {orphaned_accounts} orphaned account(s). "
                "Validate ownership and disable accounts that no longer have a business need."
            )
        })

    if privileged_without_mfa > 0:
        recommendations.append({
            "Priority": "CRITICAL",
            "Category": "Privileged Access",
            "Recommendation": (
                f"Enforce MFA for {privileged_without_mfa} privileged account(s) "
                "and review least-privilege alignment."
            )
        })

    if unmanaged_assets > 0:
        recommendations.append({
            "Priority": "HIGH",
            "Category": "Asset Coverage",
            "Recommendation": (
                f"Investigate {unmanaged_assets} unmanaged asset(s), confirm ownership, "
                "and enroll them in approved security controls."
            )
        })

    if critical_coverage_gaps > 0:
        recommendations.append({
            "Priority": "HIGH",
            "Category": "Connector Coverage",
            "Recommendation": (
                f"Resolve {critical_coverage_gaps} critical connector coverage gap(s) "
                "to improve enterprise asset visibility."
            )
        })

    if caasm_score < 50:
        recommendations.append({
            "Priority": "HIGH",
            "Category": "Executive Risk",
            "Recommendation": (
                f"The current CAASM score is {caasm_score}. "
                "Create a 30-day visibility and identity-risk improvement plan."
            )
        })

    critical_policy_findings = [
        item
        for item in policy_findings
        if item.get("Priority") == "CRITICAL"
    ]

    if critical_policy_findings:
        recommendations.append({
            "Priority": "CRITICAL",
            "Category": "Policy Findings",
            "Recommendation": (
                f"Review and remediate {len(critical_policy_findings)} "
                "critical CAASM policy finding(s)."
            )
        })

    disconnected_sources = [
        item
        for item in coverage_gap_findings
        if not item.get("Connected", True)
    ]

    if disconnected_sources:
        source_names = ", ".join(
            item.get("Source", "Unknown")
            for item in disconnected_sources
        )

        recommendations.append({
            "Priority": "HIGH",
            "Category": "Connector Integration",
            "Recommendation": (
                f"Establish missing connector integrations for: {source_names}."
            )
        })

    if not recommendations:
        recommendations.append({
            "Priority": "STANDARD",
            "Category": "Monitoring",
            "Recommendation": (
                "Maintain recurring CAASM assessments and validate connector health regularly."
            )
        })

    priority_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "STANDARD": 2
    }

    return sorted(
        recommendations,
        key=lambda item: priority_rank.get(
            item.get("Priority", "STANDARD"),
            99
        )
    )
