"""Microsoft Defender for Cloud posture and threat discovery."""

from datetime import date, datetime

from azure.mgmt.security import SecurityCenter


PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def discover_azure_security_posture(
    credential,
    subscription_id,
    asc_location="centralus",
):
    """Collect Defender posture while preserving partial results."""

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

    scope = _subscription_scope(subscription_id)
    errors = []

    secure_scores = _collect_component(
        component="secure_scores",
        loader=lambda: client.secure_scores.list(),
        serializer=_serialize_secure_score,
        errors=errors,
    )

    secure_score_controls = _collect_component(
        component="secure_score_controls",
        loader=lambda: client.secure_score_controls.list(),
        serializer=_serialize_secure_score_control,
        errors=errors,
    )

    assessment_metadata = _collect_component(
        component="assessment_metadata",
        loader=lambda: (
            client.assessments_metadata.list_by_subscription()
        ),
        serializer=_serialize_assessment_metadata,
        errors=errors,
    )

    metadata_by_name = {
        str(item.get("name") or ""): item
        for item in assessment_metadata
        if item.get("name")
    }

    assessments = _collect_component(
        component="assessments",
        loader=lambda: client.assessments.list(scope=scope),
        serializer=lambda assessment: _serialize_assessment(
            assessment,
            metadata_by_name=metadata_by_name,
        ),
        errors=errors,
    )

    alerts = _collect_component(
        component="alerts",
        loader=lambda: client.alerts.list(),
        serializer=_serialize_alert,
        errors=errors,
    )

    pricing_plans = _collect_component(
        component="pricing_plans",
        loader=lambda: client.pricings.list(
            scope_id=scope
        ),
        serializer=_serialize_pricing,
        errors=errors,
    )

    assessments.sort(
        key=lambda item: (
            PRIORITY_ORDER.get(
                str(item.get("priority", "INFO")).upper(),
                99,
            ),
            str(item.get("display_name") or "").lower(),
        )
    )

    alerts.sort(
        key=lambda item: (
            PRIORITY_ORDER.get(
                str(item.get("priority", "INFO")).upper(),
                99,
            ),
            str(item.get("time_generated_utc") or ""),
        )
    )

    collected_count = sum(
        len(items)
        for items in (
            secure_scores,
            secure_score_controls,
            assessment_metadata,
            assessments,
            alerts,
            pricing_plans,
        )
    )

    if errors and collected_count:
        discovery_status = "PARTIAL"
    elif errors:
        discovery_status = "FAILED"
    else:
        discovery_status = "COMPLETE"

    return {
        "subscription_id": subscription_id,
        "asc_location": asc_location,
        "discovery_status": discovery_status,
        "errors": errors,
        "secure_scores": secure_scores,
        "secure_score_controls": secure_score_controls,
        "assessment_metadata": assessment_metadata,
        "assessments": assessments,
        "alerts": alerts,
        "pricing_plans": pricing_plans,
        "summary": _build_summary(
            secure_scores=secure_scores,
            secure_score_controls=secure_score_controls,
            assessments=assessments,
            alerts=alerts,
            pricing_plans=pricing_plans,
        ),
    }


def _collect_component(
    component,
    loader,
    serializer,
    errors,
):
    """Collect one SDK component without discarding other data."""

    try:
        return [
            serializer(item)
            for item in _iter_items(loader())
        ]
    except Exception as exc:
        errors.append(
            {
                "component": component,
                "error_type": type(exc).__name__,
                "message": str(exc),
            }
        )
        return []


def _iter_items(result):
    """Normalize Azure paged and list response objects."""

    if result is None:
        return []

    value = getattr(result, "value", None)

    if value is not None:
        return list(value)

    return list(result)


def _subscription_scope(subscription_id):
    """Build the Azure subscription resource scope."""

    return f"/subscriptions/{subscription_id}"


def _serialize_secure_score(score):
    """Convert a Defender secure score to a dictionary."""

    current = _safe_float(
        getattr(score, "current", None)
    )
    maximum = _safe_float(
        getattr(score, "max", None)
    )
    sdk_percentage = _safe_float(
        getattr(score, "percentage", None)
    )

    percentage = sdk_percentage

    if percentage is None and current is not None and maximum:
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


def _serialize_secure_score_control(control):
    """Convert a secure-score control to a dictionary."""

    definition = getattr(control, "definition", None)

    current = _safe_float(
        getattr(control, "current", None)
    )
    maximum = _safe_float(
        getattr(control, "max", None)
    )
    percentage = _safe_float(
        getattr(control, "percentage", None)
    )

    if percentage is None and current is not None and maximum:
        percentage = round(
            (current / maximum) * 100,
            2,
        )

    return {
        "name": getattr(control, "name", None),
        "display_name": getattr(
            control,
            "display_name",
            None,
        ),
        "description": getattr(
            definition,
            "description",
            None,
        ),
        "current": current,
        "maximum": maximum,
        "percentage": percentage,
        "weight": _safe_float(
            getattr(control, "weight", None)
        ),
        "healthy_resources": _safe_int(
            getattr(
                control,
                "healthy_resource_count",
                None,
            )
        ),
        "unhealthy_resources": _safe_int(
            getattr(
                control,
                "unhealthy_resource_count",
                None,
            )
        ),
        "not_applicable_resources": _safe_int(
            getattr(
                control,
                "not_applicable_resource_count",
                None,
            )
        ),
        "id": getattr(control, "id", None),
    }


def _serialize_assessment_metadata(metadata):
    """Convert recommendation metadata without exposing secrets."""

    return {
        "name": getattr(metadata, "name", None),
        "display_name": getattr(
            metadata,
            "display_name",
            None,
        ),
        "description": getattr(
            metadata,
            "description",
            None,
        ),
        "remediation_description": getattr(
            metadata,
            "remediation_description",
            None,
        ),
        "severity": str(
            getattr(metadata, "severity", "")
            or ""
        ),
        "categories": _normalize_list(
            getattr(metadata, "categories", None)
        ),
        "threats": _normalize_list(
            getattr(metadata, "threats", None)
        ),
        "tactics": _normalize_list(
            getattr(metadata, "tactics", None)
        ),
        "techniques": _normalize_list(
            getattr(metadata, "techniques", None)
        ),
        "user_impact": getattr(
            metadata,
            "user_impact",
            None,
        ),
        "implementation_effort": getattr(
            metadata,
            "implementation_effort",
            None,
        ),
        "assessment_type": getattr(
            metadata,
            "assessment_type",
            None,
        ),
        "preview": bool(
            getattr(metadata, "preview", False)
        ),
        "id": getattr(metadata, "id", None),
    }


def _serialize_assessment(
    assessment,
    metadata_by_name=None,
):
    """Convert and enrich a Defender assessment."""

    metadata_by_name = metadata_by_name or {}

    status = getattr(assessment, "status", None)
    resource_details = getattr(
        assessment,
        "resource_details",
        None,
    )
    embedded_metadata = getattr(
        assessment,
        "metadata",
        None,
    )
    assessment_name = getattr(
        assessment,
        "name",
        None,
    )

    metadata = _metadata_dictionary(
        embedded_metadata,
        fallback=metadata_by_name.get(
            str(assessment_name or ""),
            {},
        ),
    )

    status_code = str(
        getattr(status, "code", "")
        or ""
    )
    severity = str(
        metadata.get("severity")
        or ""
    )
    priority = _assessment_priority(
        status_code=status_code,
        severity=severity,
    )

    links = getattr(assessment, "links", None)

    return {
        "name": assessment_name,
        "display_name": (
            getattr(
                assessment,
                "display_name",
                None,
            )
            or metadata.get("display_name")
        ),
        "status_code": status_code,
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
        "first_evaluation_date": _isoformat(
            getattr(
                status,
                "first_evaluation_date",
                None,
            )
        ),
        "status_change_date": _isoformat(
            getattr(
                status,
                "status_change_date",
                None,
            )
        ),
        "severity": severity,
        "priority": priority,
        "risk_score": _priority_score(priority),
        "resource_source": getattr(
            resource_details,
            "source",
            None,
        ),
        "resource_id": _resource_id(
            resource_details,
            fallback=getattr(
                assessment,
                "id",
                None,
            ),
        ),
        "description": metadata.get(
            "description"
        ),
        "remediation_description": metadata.get(
            "remediation_description"
        ),
        "categories": metadata.get(
            "categories",
            [],
        ),
        "threats": metadata.get(
            "threats",
            [],
        ),
        "tactics": metadata.get(
            "tactics",
            [],
        ),
        "techniques": metadata.get(
            "techniques",
            [],
        ),
        "user_impact": metadata.get(
            "user_impact"
        ),
        "implementation_effort": metadata.get(
            "implementation_effort"
        ),
        "portal_uri": getattr(
            links,
            "azure_portal_uri",
            None,
        ),
        "id": getattr(assessment, "id", None),
    }


def _metadata_dictionary(metadata, fallback):
    """Normalize embedded or separately discovered metadata."""

    if metadata is None:
        return dict(fallback or {})

    serialized = _serialize_assessment_metadata(
        metadata
    )

    for key, value in (fallback or {}).items():
        if serialized.get(key) in (
            None,
            "",
            [],
        ):
            serialized[key] = value

    return serialized


def _serialize_alert(alert):
    """Convert a Defender security alert to a dictionary."""

    severity = str(
        getattr(alert, "severity", "")
        or ""
    )
    priority = _alert_priority(severity)

    return {
        "name": getattr(alert, "name", None),
        "system_alert_id": getattr(
            alert,
            "system_alert_id",
            None,
        ),
        "display_name": getattr(
            alert,
            "alert_display_name",
            None,
        ),
        "alert_type": getattr(
            alert,
            "alert_type",
            None,
        ),
        "description": getattr(
            alert,
            "description",
            None,
        ),
        "severity": severity,
        "priority": priority,
        "risk_score": _priority_score(priority),
        "status": str(
            getattr(alert, "status", "")
            or ""
        ),
        "intent": getattr(alert, "intent", None),
        "compromised_entity": getattr(
            alert,
            "compromised_entity",
            None,
        ),
        "product_name": getattr(
            alert,
            "product_name",
            None,
        ),
        "vendor_name": getattr(
            alert,
            "vendor_name",
            None,
        ),
        "time_generated_utc": _isoformat(
            getattr(
                alert,
                "time_generated_utc",
                None,
            )
        ),
        "start_time_utc": _isoformat(
            getattr(
                alert,
                "start_time_utc",
                None,
            )
        ),
        "end_time_utc": _isoformat(
            getattr(
                alert,
                "end_time_utc",
                None,
            )
        ),
        "remediation_steps": _normalize_list(
            getattr(
                alert,
                "remediation_steps",
                None,
            )
        ),
        "techniques": _normalize_list(
            getattr(alert, "techniques", None)
        ),
        "sub_techniques": _normalize_list(
            getattr(
                alert,
                "sub_techniques",
                None,
            )
        ),
        "is_incident": bool(
            getattr(alert, "is_incident", False)
        ),
        "alert_uri": getattr(
            alert,
            "alert_uri",
            None,
        ),
        "id": getattr(alert, "id", None),
    }


def _serialize_pricing(pricing):
    """Convert a Defender plan configuration."""

    return {
        "name": getattr(pricing, "name", None),
        "pricing_tier": getattr(
            pricing,
            "pricing_tier",
            None,
        ),
        "sub_plan": getattr(
            pricing,
            "sub_plan",
            None,
        ),
        "resources_coverage_status": getattr(
            pricing,
            "resources_coverage_status",
            None,
        ),
        "enablement_time": _isoformat(
            getattr(
                pricing,
                "enablement_time",
                None,
            )
        ),
        "inherited": getattr(
            pricing,
            "inherited",
            None,
        ),
        "inherited_from": getattr(
            pricing,
            "inherited_from",
            None,
        ),
        "deprecated": bool(
            getattr(pricing, "deprecated", False)
        ),
        "replaced_by": _normalize_list(
            getattr(pricing, "replaced_by", None)
        ),
        "id": getattr(pricing, "id", None),
    }


def _build_summary(
    secure_scores,
    secure_score_controls,
    assessments,
    alerts,
    pricing_plans,
):
    """Build an operational Defender posture summary."""

    return {
        "secure_scores": len(secure_scores),
        "secure_score_controls": len(
            secure_score_controls
        ),
        "assessments": len(assessments),
        "healthy": _count_value(
            assessments,
            "status_code",
            "healthy",
        ),
        "unhealthy": _count_value(
            assessments,
            "status_code",
            "unhealthy",
        ),
        "not_applicable": sum(
            1
            for assessment in assessments
            if str(
                assessment.get(
                    "status_code",
                    "",
                )
            ).lower()
            in {
                "notapplicable",
                "not_applicable",
            }
        ),
        "critical_assessments": _count_value(
            assessments,
            "priority",
            "critical",
        ),
        "high_assessments": _count_value(
            assessments,
            "priority",
            "high",
        ),
        "alerts": len(alerts),
        "critical_alerts": _count_value(
            alerts,
            "priority",
            "critical",
        ),
        "high_alerts": _count_value(
            alerts,
            "priority",
            "high",
        ),
        "pricing_plans": len(pricing_plans),
        "standard_pricing_plans": _count_value(
            pricing_plans,
            "pricing_tier",
            "standard",
        ),
    }


def _assessment_priority(status_code, severity):
    """Map recommendation state and severity to priority."""

    if str(status_code).lower() != "unhealthy":
        return "INFO"

    severity_value = str(severity).upper()

    if severity_value == "HIGH":
        return "CRITICAL"

    if severity_value == "MEDIUM":
        return "HIGH"

    if severity_value == "LOW":
        return "MEDIUM"

    return "HIGH"


def _alert_priority(severity):
    """Map Defender alert severity to operational priority."""

    severity_value = str(severity).upper()

    if severity_value == "HIGH":
        return "CRITICAL"

    if severity_value == "MEDIUM":
        return "HIGH"

    if severity_value == "LOW":
        return "MEDIUM"

    if severity_value in {
        "INFORMATIONAL",
        "INFO",
    }:
        return "INFO"

    return "HIGH"


def _priority_score(priority):
    """Return a normalized risk score for a priority."""

    return {
        "CRITICAL": 90,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFO": 0,
    }.get(str(priority).upper(), 0)


def _resource_id(resource_details, fallback=None):
    """Extract the actual affected Azure resource identifier."""

    if resource_details is None:
        return fallback

    for attribute_name in (
        "id",
        "workspace_id",
        "source_computer_id",
        "vmuuid",
        "machine_name",
    ):
        value = getattr(
            resource_details,
            attribute_name,
            None,
        )

        if value:
            return value

    return fallback


def _count_value(rows, field, expected):
    """Count normalized field values."""

    return sum(
        1
        for row in rows
        if str(row.get(field, "")).lower()
        == str(expected).lower()
    )


def _normalize_list(value):
    """Convert Azure list-like fields to plain lists."""

    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    try:
        return list(value)
    except TypeError:
        return [value]


def _isoformat(value):
    """Convert Azure date values to ISO-8601 strings."""

    if value is None:
        return None

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return str(value)


def _safe_float(value):
    """Convert numeric SDK values to float when possible."""

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value):
    """Convert numeric SDK values to integers when possible."""

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None
