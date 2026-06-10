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


def get_adapter_for_action(action_type):
    return SUPPORTED_ACTIONS.get(
        action_type,
        "NO_APPROVED_ADAPTER"
    )


def build_execution_plan(action_type, finding):
    from remediation_targeting import extract_resource_target

    target = extract_resource_target(
        action_type=action_type,
        finding=finding
    )

    adapter = get_adapter_for_action(action_type)

    return {
        "adapter": adapter,
        "action_type": action_type,
        "finding": finding,
        "resource_type": target.get("resource_type"),
        "resource_id": target.get("resource_id"),
        "target_supported": target.get("supported", False),
        "execution_mode": "Simulation",
        "live_execution_enabled": False,
        "message": (
            "Dry-run execution plan created. "
            "No AWS resource changes were performed."
        )
    }


def get_adapter_readiness_matrix():
    return [
        {
            "Adapter": "IAM_REVIEW",
            "Action Type": "Generate IAM MFA and Access Key Review Task",
            "Resource Type": "IAM_USER",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Simulation Only"
        },
        {
            "Adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "Action Type": "Generate S3 Exposure Remediation Task",
            "Resource Type": "S3_BUCKET",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Candidate for Controlled Testing"
        },
        {
            "Adapter": "INCIDENT_RESPONSE_TASK",
            "Action Type": "Generate Incident Response Investigation Task",
            "Resource Type": "SECURITY_INCIDENT",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only"
        },
        {
            "Adapter": "CSPM_REMEDIATION_TASK",
            "Action Type": "Generate Cloud Security Posture Remediation Task",
            "Resource Type": "CSPM_FINDING",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only"
        },
        {
            "Adapter": "MONITORING_REVIEW_TASK",
            "Action Type": "Generate Monitoring Review Task",
            "Resource Type": "MONITORING_FINDING",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only"
        }
    ]
