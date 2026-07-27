from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import azure_security_posture


class ValueResponse:
    def __init__(self, value):
        self.value = value


def test_subscription_scope():
    assert (
        azure_security_posture._subscription_scope(
            "subscription-id"
        )
        == "/subscriptions/subscription-id"
    )


def test_discover_complete_defender_posture(monkeypatch):
    score = SimpleNamespace(
        name="ascScore",
        display_name="Microsoft Defender for Cloud",
        current=42,
        max=60,
        percentage=None,
        weight=1,
        id="/scores/ascScore",
    )

    control = SimpleNamespace(
        name="protect-management-ports",
        display_name="Protect management ports",
        current=4,
        max=8,
        percentage=50,
        weight=2,
        healthy_resource_count=4,
        unhealthy_resource_count=2,
        not_applicable_resource_count=1,
        definition=SimpleNamespace(
            description="Protect administrative access."
        ),
        id="/controls/protect-management-ports",
    )

    metadata = SimpleNamespace(
        name="assessment-id",
        display_name="Enable secure transfer",
        description="Secure transfer is disabled.",
        remediation_description="Enable HTTPS-only traffic.",
        severity="High",
        categories=["Data"],
        threats=["DataExfiltration"],
        tactics=["Exfiltration"],
        techniques=["T1048"],
        user_impact="Low",
        implementation_effort="Low",
        assessment_type="BuiltIn",
        preview=False,
        id="/metadata/assessment-id",
    )

    assessment = SimpleNamespace(
        name="assessment-id",
        display_name=None,
        status=SimpleNamespace(
            code="Unhealthy",
            cause="Policy",
            description="Recommendation is unresolved.",
            first_evaluation_date=datetime(
                2026,
                7,
                1,
                tzinfo=timezone.utc,
            ),
            status_change_date=datetime(
                2026,
                7,
                20,
                tzinfo=timezone.utc,
            ),
        ),
        resource_details=SimpleNamespace(
            source="Azure",
            id=(
                "/subscriptions/subscription-id/"
                "resourceGroups/rg/providers/"
                "Microsoft.Storage/storageAccounts/account"
            ),
        ),
        metadata=None,
        links=SimpleNamespace(
            azure_portal_uri="https://portal.example"
        ),
        id="/assessments/assessment-id",
    )

    alert = SimpleNamespace(
        name="alert-name",
        system_alert_id="system-alert-id",
        alert_display_name="Suspicious process",
        alert_type="VM_Threat",
        description="Suspicious activity detected.",
        severity="High",
        status="Active",
        intent="Execution",
        compromised_entity="vm-01",
        product_name="Defender for Servers",
        vendor_name="Microsoft",
        time_generated_utc=datetime(
            2026,
            7,
            24,
            tzinfo=timezone.utc,
        ),
        start_time_utc=None,
        end_time_utc=None,
        remediation_steps=["Isolate the host"],
        techniques=["T1059"],
        sub_techniques=["T1059.001"],
        is_incident=True,
        alert_uri="https://portal.example/alert",
        id="/alerts/alert-name",
    )

    pricing = SimpleNamespace(
        name="VirtualMachines",
        pricing_tier="Standard",
        sub_plan="P2",
        resources_coverage_status="FullyCovered",
        enablement_time=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        inherited="False",
        inherited_from=None,
        deprecated=False,
        replaced_by=None,
        id="/pricings/VirtualMachines",
    )

    class FakeSecurityCenter:
        def __init__(
            self,
            credential,
            subscription_id,
            asc_location,
        ):
            assert credential == "credential"
            assert subscription_id == "subscription-id"
            assert asc_location == "centralus"

            self.secure_scores = SimpleNamespace(
                list=lambda: [score]
            )
            self.secure_score_controls = (
                SimpleNamespace(
                    list=lambda: [control]
                )
            )
            self.assessments_metadata = (
                SimpleNamespace(
                    list_by_subscription=lambda: [
                        metadata
                    ]
                )
            )
            self.assessments = SimpleNamespace(
                list=self._list_assessments
            )
            self.alerts = SimpleNamespace(
                list=lambda: [alert]
            )
            self.pricings = SimpleNamespace(
                list=self._list_pricing
            )

        @staticmethod
        def _list_assessments(scope):
            assert scope == (
                "/subscriptions/subscription-id"
            )
            return [assessment]

        @staticmethod
        def _list_pricing(scope_id):
            assert scope_id == (
                "/subscriptions/subscription-id"
            )
            return ValueResponse([pricing])

    monkeypatch.setattr(
        azure_security_posture,
        "SecurityCenter",
        FakeSecurityCenter,
    )

    result = (
        azure_security_posture
        .discover_azure_security_posture(
            credential="credential",
            subscription_id="subscription-id",
        )
    )

    assert result["discovery_status"] == "COMPLETE"
    assert result["errors"] == []

    assert result["summary"] == {
        "secure_scores": 1,
        "secure_score_controls": 1,
        "assessments": 1,
        "healthy": 0,
        "unhealthy": 1,
        "not_applicable": 0,
        "critical_assessments": 1,
        "high_assessments": 0,
        "alerts": 1,
        "critical_alerts": 1,
        "high_alerts": 0,
        "pricing_plans": 1,
        "standard_pricing_plans": 1,
    }

    assert (
        result["secure_scores"][0]["percentage"]
        == 70.0
    )
    assert (
        result["secure_score_controls"][0]
        ["unhealthy_resources"]
        == 2
    )
    assert (
        result["assessments"][0]["resource_id"]
        .endswith("/storageAccounts/account")
    )
    assert (
        result["assessments"][0]["severity"]
        == "High"
    )
    assert (
        result["assessments"][0]["priority"]
        == "CRITICAL"
    )
    assert (
        result["assessments"][0]
        ["remediation_description"]
        == "Enable HTTPS-only traffic."
    )
    assert (
        result["alerts"][0]["priority"]
        == "CRITICAL"
    )
    assert (
        result["pricing_plans"][0]
        ["pricing_tier"]
        == "Standard"
    )


def test_partial_failure_preserves_available_results(
    monkeypatch,
):
    class BrokenOperation:
        @staticmethod
        def list(*args, **kwargs):
            raise RuntimeError("API unavailable")

    class FakeSecurityCenter:
        def __init__(self, **kwargs):
            self.secure_scores = SimpleNamespace(
                list=lambda: []
            )
            self.secure_score_controls = (
                BrokenOperation()
            )
            self.assessments_metadata = (
                SimpleNamespace(
                    list_by_subscription=lambda: []
                )
            )
            self.assessments = SimpleNamespace(
                list=lambda scope: []
            )
            self.alerts = SimpleNamespace(
                list=lambda: [
                    SimpleNamespace(
                        severity="Low"
                    )
                ]
            )
            self.pricings = SimpleNamespace(
                list=lambda scope_id: ValueResponse(
                    []
                )
            )

    monkeypatch.setattr(
        azure_security_posture,
        "SecurityCenter",
        FakeSecurityCenter,
    )

    result = (
        azure_security_posture
        .discover_azure_security_posture(
            credential="credential",
            subscription_id="subscription-id",
        )
    )

    assert result["discovery_status"] == "PARTIAL"
    assert len(result["alerts"]) == 1
    assert result["errors"][0]["component"] == (
        "secure_score_controls"
    )


def test_assessment_uses_actual_resource_id():
    assessment = SimpleNamespace(
        name="assessment",
        display_name="Assessment",
        status=SimpleNamespace(
            code="Healthy"
        ),
        resource_details=SimpleNamespace(
            source="Azure",
            id="/subscriptions/sub/resource",
        ),
        metadata=None,
        links=None,
        id="/assessment/id",
    )

    result = (
        azure_security_posture
        ._serialize_assessment(assessment)
    )

    assert result["resource_source"] == "Azure"
    assert result["resource_id"] == (
        "/subscriptions/sub/resource"
    )
    assert result["priority"] == "INFO"


@pytest.mark.parametrize(
    ("status", "severity", "expected"),
    [
        ("Unhealthy", "High", "CRITICAL"),
        ("Unhealthy", "Medium", "HIGH"),
        ("Unhealthy", "Low", "MEDIUM"),
        ("Unhealthy", "", "HIGH"),
        ("Healthy", "High", "INFO"),
        ("NotApplicable", "High", "INFO"),
    ],
)
def test_assessment_priority(
    status,
    severity,
    expected,
):
    assert (
        azure_security_posture
        ._assessment_priority(
            status,
            severity,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("High", "CRITICAL"),
        ("Medium", "HIGH"),
        ("Low", "MEDIUM"),
        ("Informational", "INFO"),
        ("", "HIGH"),
    ],
)
def test_alert_priority(severity, expected):
    assert (
        azure_security_posture
        ._alert_priority(severity)
        == expected
    )


def test_iter_items_supports_value_response():
    assert azure_security_posture._iter_items(
        ValueResponse([1, 2])
    ) == [1, 2]


def test_discover_requires_credential():
    with pytest.raises(
        ValueError,
        match="credential",
    ):
        (
            azure_security_posture
            .discover_azure_security_posture(
                credential=None,
                subscription_id="subscription-id",
            )
        )


def test_discover_requires_subscription_id():
    with pytest.raises(
        ValueError,
        match="subscription ID",
    ):
        (
            azure_security_posture
            .discover_azure_security_posture(
                credential="credential",
                subscription_id="",
            )
        )


def test_discover_requires_location():
    with pytest.raises(
        ValueError,
        match="location",
    ):
        (
            azure_security_posture
            .discover_azure_security_posture(
                credential="credential",
                subscription_id="subscription-id",
                asc_location="",
            )
        )


def test_safe_numeric_helpers():
    assert (
        azure_security_posture._safe_float(
            "3.5"
        )
        == 3.5
    )
    assert (
        azure_security_posture._safe_float(
            "invalid"
        )
        is None
    )
    assert azure_security_posture._safe_int(
        "4"
    ) == 4
    assert (
        azure_security_posture._safe_int(
            "invalid"
        )
        is None
    )


def test_isoformat_datetime():
    value = datetime(
        2026,
        7,
        24,
        tzinfo=timezone.utc,
    )

    assert (
        azure_security_posture._isoformat(value)
        == "2026-07-24T00:00:00+00:00"
    )
