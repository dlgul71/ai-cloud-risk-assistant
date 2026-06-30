from dataclasses import dataclass

from app_config import settings


@dataclass
class RemediationGuardrails:
    live_execution_enabled: bool = False
    require_human_approval: bool = True
    require_confirmation_phrase: bool = True
    allowed_actions: tuple = (
        "Generate IAM MFA and Access Key Review Task",
        "Generate S3 Exposure Remediation Task",
        "Generate Incident Response Investigation Task",
        "Generate Cloud Security Posture Remediation Task",
        "Generate Monitoring Review Task",
    )


GUARDRAILS = RemediationGuardrails(
    live_execution_enabled=settings.live_remediation_enabled,
)


def validate_live_execution_request(
    action_type,
    approval_status,
    execution_mode,
    confirmation_phrase=""
):
    if execution_mode != "Live":
        return {
            "allowed": True,
            "mode": "Simulation",
            "message": "Simulation mode approved. No AWS resources will be modified."
        }

    if not GUARDRAILS.live_execution_enabled:
        return {
            "allowed": False,
            "mode": "Live",
            "message": "Live AWS execution is disabled by platform guardrails."
        }

    if GUARDRAILS.require_human_approval and approval_status != "Approved":
        return {
            "allowed": False,
            "mode": "Live",
            "message": "Human approval is required before live execution."
        }

    if action_type not in GUARDRAILS.allowed_actions:
        return {
            "allowed": False,
            "mode": "Live",
            "message": "This action type is not approved for live execution."
        }

    if (
        GUARDRAILS.require_confirmation_phrase
        and confirmation_phrase != "AUTHORIZE LIVE AWS REMEDIATION"
    ):
        return {
            "allowed": False,
            "mode": "Live",
            "message": "The required live execution confirmation phrase was not provided."
        }

    return {
        "allowed": True,
        "mode": "Live",
        "message": "Live execution request passed platform guardrails."
    }
