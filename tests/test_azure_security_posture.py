import pytest

import azure_security_posture


def test_subscription_scope():
    assert (
        azure_security_posture._subscription_scope(
            "subscription-id"
        )
        == "/subscriptions/subscription-id"
    )


def test_discover_azure_security_posture(monkeypatch):
    class FakeSecureScore:
        name = "ascScore"
        display_name = "Microsoft Defender for Cloud"
        current = 42
        max = 60
        weight = 1
        id = "/subscriptions/sub/providers/security/scores/ascScore"

    class FakeStatus:
        code = "Unhealthy"
        cause = "Policy"
        description = "Security recommendation is unresolved."

    class FakeResourceDetails:
        source = "Azure"

    class FakeAssessment:
        name = "assessment-id"
        display_name = "Enable secure transfer"
        status = FakeStatus()
        resource_details = FakeResourceDetails()
        id = (
            "/subscriptions/sub/providers/"
            "Microsoft.Security/assessments/assessment-id"
        )

    class FakeSecureScores:
        def list(self):
            return [FakeSecureScore()]

    class FakeAssessments:
        def list(self, scope):
            assert scope == "/subscriptions/subscription-id"
            return [FakeAssessment()]

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

            self.secure_scores = FakeSecureScores()
            self.assessments = FakeAssessments()

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

    assert result["summary"] == {
        "secure_scores": 1,
        "assessments": 1,
        "healthy": 0,
        "unhealthy": 1,
        "not_applicable": 0,
    }

    assert result["secure_scores"][0]["percentage"] == 70.0
    assert (
        result["assessments"][0]["status_code"]
        == "Unhealthy"
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


def test_safe_float_handles_invalid_value():
    assert azure_security_posture._safe_float("invalid") is None
