"""Azure storage-account exposure and configuration analysis."""


def analyze_storage_exposure(storage_accounts):
    """Analyze discovered Azure storage accounts for security risks."""

    accounts = list(storage_accounts or [])
    findings = []

    for account in accounts:
        findings.extend(_analyze_account(account))

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "")
        ).strip().lower()

        if severity in severity_counts:
            severity_counts[severity] += 1

    exposed_accounts = {
        finding["storage_account"]
        for finding in findings
        if finding.get("severity") in {"Critical", "High"}
    }

    return {
        "storage_accounts": accounts,
        "findings": findings,
        "summary": {
            "storage_accounts": len(accounts),
            "findings": len(findings),
            "exposed_accounts": len(exposed_accounts),
            **severity_counts,
        },
    }


def _analyze_account(account):
    """Return security findings for one storage account."""

    account_name = account.get("name") or "Unknown"
    resource_id = account.get("id")
    findings = []

    public_network_access = _normalize(
        account.get("public_network_access")
    )
    default_action = _normalize(
        account.get("network_default_action")
    )
    minimum_tls = _normalize(
        account.get("minimum_tls_version")
    )

    if (
        public_network_access == "enabled"
        and default_action != "deny"
    ):
        findings.append(
            _finding(
                account_name=account_name,
                resource_id=resource_id,
                severity="High",
                control="Public Network Exposure",
                description=(
                    "Public network access is enabled and the "
                    "default network action is not Deny."
                ),
                recommendation=(
                    "Disable public network access or set the "
                    "default network rule action to Deny."
                ),
            )
        )

    if account.get("https_only") is not True:
        findings.append(
            _finding(
                account_name=account_name,
                resource_id=resource_id,
                severity="High",
                control="Secure Transfer Required",
                description=(
                    "HTTPS-only traffic enforcement is not enabled."
                ),
                recommendation=(
                    "Enable secure transfer required for the "
                    "storage account."
                ),
            )
        )

    if minimum_tls not in {"tls1_2", "tls1_3"}:
        findings.append(
            _finding(
                account_name=account_name,
                resource_id=resource_id,
                severity="Medium",
                control="Minimum TLS Version",
                description=(
                    "The minimum TLS version is below TLS 1.2 "
                    "or is not configured."
                ),
                recommendation=(
                    "Set the minimum TLS version to TLS 1.2 "
                    "or later."
                ),
            )
        )

    if account.get("allow_shared_key_access") is not False:
        findings.append(
            _finding(
                account_name=account_name,
                resource_id=resource_id,
                severity="Medium",
                control="Shared Key Authorization",
                description=(
                    "Shared-key authorization is enabled or its "
                    "state could not be verified."
                ),
                recommendation=(
                    "Disable shared-key authorization where "
                    "workloads support Microsoft Entra ID."
                ),
            )
        )

    return findings


def _finding(
    account_name,
    resource_id,
    severity,
    control,
    description,
    recommendation,
):
    """Create a normalized storage-security finding."""

    return {
        "storage_account": account_name,
        "severity": severity,
        "control": control,
        "description": description,
        "recommendation": recommendation,
        "resource_id": resource_id,
    }


def _normalize(value):
    """Normalize SDK and string values for comparison."""

    return str(value or "").strip().lower()
