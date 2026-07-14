"""Unified cloud-risk scoring for DGS Sentinel AI."""


SECURITY_HUB_FINDING_WEIGHT = 20
GUARDDUTY_FINDING_WEIGHT = 30

AZURE_CRITICAL_FINDING_WEIGHT = 20
AZURE_HIGH_FINDING_WEIGHT = 10
AZURE_MEDIUM_FINDING_WEIGHT = 5

MAX_RISK_SCORE = 100


def calculate_asset_risk(asset):
    """Calculate a basic risk score for a discovered cloud asset."""
    score = 0

    if asset.get("public_ip"):
        score += 25

    if asset.get("state") == "running":
        score += 15

    if asset.get("asset_type") == "EC2":
        score += 10

    return score


def calculate_unified_risk(
    base_risk,
    securityhub_count,
    guardduty_count,
    azure_critical_count=0,
    azure_high_count=0,
    azure_medium_count=0,
):
    """Calculate a capped multi-cloud risk score.

    Existing AWS scoring remains unchanged. Azure findings are optional,
    allowing existing three-argument callers to continue working.
    """

    score = _nonnegative_number(base_risk)

    score += (
        _nonnegative_number(securityhub_count)
        * SECURITY_HUB_FINDING_WEIGHT
    )
    score += (
        _nonnegative_number(guardduty_count)
        * GUARDDUTY_FINDING_WEIGHT
    )
    score += (
        _nonnegative_number(azure_critical_count)
        * AZURE_CRITICAL_FINDING_WEIGHT
    )
    score += (
        _nonnegative_number(azure_high_count)
        * AZURE_HIGH_FINDING_WEIGHT
    )
    score += (
        _nonnegative_number(azure_medium_count)
        * AZURE_MEDIUM_FINDING_WEIGHT
    )

    return min(score, MAX_RISK_SCORE)


def _nonnegative_number(value):
    """Convert a value to a nonnegative numeric value."""

    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0

    return max(number, 0)


def summarize_azure_findings(
    network_exposure=None,
    storage_exposure=None,
):
    """Combine Azure network and storage severity counts."""

    network_summary = (
        (network_exposure or {}).get("summary") or {}
    )
    storage_summary = (
        (storage_exposure or {}).get("summary") or {}
    )

    critical = (
        _nonnegative_count(
            network_summary.get("critical_findings", 0)
        )
        + _nonnegative_count(
            storage_summary.get("critical", 0)
        )
    )

    high = (
        _nonnegative_count(
            network_summary.get("high_findings", 0)
        )
        + _nonnegative_count(
            storage_summary.get("high", 0)
        )
    )

    medium = (
        _nonnegative_count(
            network_summary.get("medium_findings", 0)
        )
        + _nonnegative_count(
            storage_summary.get("medium", 0)
        )
    )

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "total": critical + high + medium,
    }


def _nonnegative_count(value):
    """Convert a value to a nonnegative integer count."""

    try:
        count = int(float(value))
    except (TypeError, ValueError):
        return 0

    return max(count, 0)
