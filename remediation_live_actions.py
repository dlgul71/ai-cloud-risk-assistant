from remediation_guardrails import validate_live_execution_request


SUPPORTED_ACTIONS = {
    "Generate IAM MFA and Access Key Review Task": "IAM_REVIEW",
    "Generate S3 Exposure Remediation Task": "S3_BLOCK_PUBLIC_ACCESS",
    "Generate Incident Response Investigation Task": "INCIDENT_RESPONSE_TASK",
    "Generate Cloud Security Posture Remediation Task": "CSPM_REMEDIATION_TASK",
    "Generate Monitoring Review Task": "MONITORING_REVIEW_TASK",
}


def execute_controlled_action(
    action_type,
    finding,
    approval_status,
    execution_mode="Simulation",
    confirmation_phrase=""
):
    guardrail_result = validate_live_execution_request(
        action_type=action_type,
        approval_status=approval_status,
        execution_mode=execution_mode,
        confirmation_phrase=confirmation_phrase
    )

    if not guardrail_result.get("allowed"):
        return {
            "status": "BLOCKED",
            "mode": execution_mode,
            "action_type": action_type,
            "finding": finding,
            "message": guardrail_result.get("message")
        }

    adapter = SUPPORTED_ACTIONS.get(action_type)

    if not adapter:
        return {
            "status": "BLOCKED",
            "mode": execution_mode,
            "action_type": action_type,
            "finding": finding,
            "message": "No approved remediation adapter exists for this action type."
        }

    if execution_mode == "Simulation":
        return {
            "status": "SIMULATED",
            "mode": "Simulation",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": "Simulation completed. No AWS resources were modified."
        }

    return {
        "status": "BLOCKED",
        "mode": "Live",
        "adapter": adapter,
        "action_type": action_type,
        "finding": finding,
        "message": (
            "Live adapter execution is not implemented yet. "
            "The request passed guardrails but no AWS modification was performed."
        )
    }
