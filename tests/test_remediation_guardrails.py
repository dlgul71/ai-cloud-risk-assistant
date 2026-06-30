from dataclasses import replace

import remediation_guardrails


S3_ACTION = "Generate S3 Exposure Remediation Task"


def test_simulation_is_allowed_when_live_execution_is_disabled(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=False,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type=S3_ACTION,
        approval_status="Pending Approval",
        execution_mode="Simulation",
    )

    assert result["allowed"] is True
    assert result["mode"] == "Simulation"


def test_live_execution_is_blocked_when_feature_is_disabled(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=False,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type=S3_ACTION,
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase="AUTHORIZE LIVE AWS REMEDIATION",
    )

    assert result["allowed"] is False
    assert "disabled" in result["message"].lower()


def test_live_execution_requires_human_approval(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=True,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type=S3_ACTION,
        approval_status="Pending Approval",
        execution_mode="Live",
        confirmation_phrase="AUTHORIZE LIVE AWS REMEDIATION",
    )

    assert result["allowed"] is False
    assert "approval" in result["message"].lower()


def test_live_execution_rejects_unapproved_action_type(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=True,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type="Unsupported Destructive Action",
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase="AUTHORIZE LIVE AWS REMEDIATION",
    )

    assert result["allowed"] is False
    assert "not approved" in result["message"].lower()


def test_live_execution_requires_exact_confirmation_phrase(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=True,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type=S3_ACTION,
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase="authorize remediation",
    )

    assert result["allowed"] is False
    assert "confirmation phrase" in result["message"].lower()


def test_live_execution_passes_all_guardrails(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_guardrails,
        "GUARDRAILS",
        replace(
            remediation_guardrails.GUARDRAILS,
            live_execution_enabled=True,
        ),
    )

    result = remediation_guardrails.validate_live_execution_request(
        action_type=S3_ACTION,
        approval_status="Approved",
        execution_mode="Live",
        confirmation_phrase="AUTHORIZE LIVE AWS REMEDIATION",
    )

    assert result["allowed"] is True
    assert result["mode"] == "Live"
