"""Azure Defender for Cloud posture discovery."""

from azure.mgmt.security import SecurityCenter


def discover_azure_security_posture(
    credential,
    subscription_id,
    asc_location="centralus",
):
    """Collect Defender for Cloud secure scores and assessments."""

    if credential is None:
        raise ValueError("Azure credential is required.")

    if not subscription_id:
        raise ValueError("Azure subscription ID is required.")

    if not asc_location:
        raise ValueError(
            "Azure Security Center location is required."
        )

    client = SecurityCenter(
        credential=credential,
        subscription_id=subscription_id,
        asc_location=asc_location,
    )

    secure_scores = [
        _serialize_secure_score(score)
        for score in client.secure_scores.list()
    ]

    assessments = [
        _serialize_assessment(assessment)
        for assessment in client.assessments.list(
            scope=_subscription_scope(subscription_id)
        )
    ]

    unhealthy_assessments = [
        assessment
        for assessment in assessments
        if assessment["status_code"].lower() == "unhealthy"
    ]

    healthy_assessments = [
        assessment
        for assessment in assessments
        if assessment["status_code"].lower() == "healthy"
    ]

    not_applicable_assessments = [
        assessment
        for assessment in assessments
        if assessment["status_code"].lower()
        in {"notapplicable", "not_applicable"}
    ]

    return {
        "subscription_id": subscription_id,
        "asc_location": asc_location,
        "secure_scores": secure_scores,
        "assessments": assessments,
        "summary": {
            "secure_scores": len(secure_scores),
            "assessments": len(assessments),
            "healthy": len(healthy_assessments),
            "unhealthy": len(unhealthy_assessments),
            "not_applicable": len(
                not_applicable_assessments
            ),
        },
    }


def _subscription_scope(subscription_id):
    """Build the Azure subscription resource scope."""

    return f"/subscriptions/{subscription_id}"


def _serialize_secure_score(score):
    """Convert an Azure secure score model to a dictionary."""

    current = _safe_float(
        getattr(score, "current", None)
    )
    maximum = _safe_float(
        getattr(score, "max", None)
    )

    percentage = None

    if current is not None and maximum:
        percentage = round(
            (current / maximum) * 100,
            2,
        )

    return {
        "name": getattr(score, "name", None),
        "display_name": getattr(
            score,
            "display_name",
            None,
        ),
        "current": current,
        "maximum": maximum,
        "percentage": percentage,
        "weight": _safe_float(
            getattr(score, "weight", None)
        ),
        "id": getattr(score, "id", None),
    }


def _serialize_assessment(assessment):
    """Convert an Azure security assessment to a dictionary."""

    status = getattr(assessment, "status", None)

    return {
        "name": getattr(assessment, "name", None),
        "display_name": getattr(
            assessment,
            "display_name",
            None,
        ),
        "status_code": str(
            getattr(status, "code", "")
            or ""
        ),
        "status_cause": getattr(
            status,
            "cause",
            None,
        ),
        "status_description": getattr(
            status,
            "description",
            None,
        ),
        "resource_id": getattr(
            assessment,
            "resource_details",
            None,
        ).source
        if getattr(
            assessment,
            "resource_details",
            None,
        ) is not None
        and hasattr(
            assessment.resource_details,
            "source",
        )
        else getattr(assessment, "id", None),
        "id": getattr(assessment, "id", None),
    }


def _safe_float(value):
    """Convert numeric SDK values to float when possible."""

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None
