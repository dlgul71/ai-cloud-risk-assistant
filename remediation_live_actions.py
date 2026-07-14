from remediation_aws_adapters import execute_s3_public_access_block
from remediation_azure_adapters import (
    execute_azure_storage_account_hardening,
)
from remediation_guardrails import validate_live_execution_request
from remediation_targeting import extract_resource_target


SUPPORTED_ACTIONS = {
    "Generate IAM MFA and Access Key Review Task": "IAM_REVIEW",
    "Generate S3 Exposure Remediation Task": "S3_BLOCK_PUBLIC_ACCESS",
    "Generate Azure Storage Hardening Task": "AZURE_STORAGE_HARDENING",
    "Generate Incident Response Investigation Task": (
        "INCIDENT_RESPONSE_TASK"
    ),
    "Generate Cloud Security Posture Remediation Task": (
        "CSPM_REMEDIATION_TASK"
    ),
    "Generate Monitoring Review Task": "MONITORING_REVIEW_TASK",
}


LIVE_ENABLED_ADAPTERS = {
    "S3_BLOCK_PUBLIC_ACCESS",
    "AZURE_STORAGE_HARDENING",
}


def execute_controlled_action(
    action_type,
    finding,
    approval_status,
    execution_mode="Simulation",
    confirmation_phrase="",
    expected_account_id=None,
    s3_client=None,
    expected_subscription_id=None,
    azure_storage_client=None,
):
    guardrail_result = validate_live_execution_request(
        action_type=action_type,
        approval_status=approval_status,
        execution_mode=execution_mode,
        confirmation_phrase=confirmation_phrase,
    )

    if not guardrail_result.get("allowed"):
        return {
            "status": "BLOCKED",
            "mode": execution_mode,
            "action_type": action_type,
            "finding": finding,
            "message": guardrail_result.get("message"),
        }

    adapter = SUPPORTED_ACTIONS.get(action_type)

    if not adapter:
        return {
            "status": "BLOCKED",
            "mode": execution_mode,
            "action_type": action_type,
            "finding": finding,
            "message": (
                "No approved remediation adapter exists "
                "for this action type."
            ),
        }

    if execution_mode == "Simulation":
        return {
            "status": "SIMULATED",
            "mode": "Simulation",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": (
                "Simulation completed. No cloud resources "
                "were modified."
            ),
        }

    if adapter not in LIVE_ENABLED_ADAPTERS:
        return {
            "status": "BLOCKED",
            "mode": "Live",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": (
                "This adapter is not enabled for live execution."
            ),
        }

    target = extract_resource_target(
        action_type=action_type,
        finding=finding,
    )

    if not target.get("supported"):
        return {
            "status": "BLOCKED",
            "mode": "Live",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": (
                "The remediation target could not be validated."
            ),
        }

    try:
        if adapter == "S3_BLOCK_PUBLIC_ACCESS":
            if not expected_account_id:
                return {
                    "status": "BLOCKED",
                    "mode": "Live",
                    "adapter": adapter,
                    "action_type": action_type,
                    "finding": finding,
                    "message": (
                        "The expected AWS account ID is required "
                        "for live S3 remediation."
                    ),
                }

            execution_result = execute_s3_public_access_block(
                bucket_name=target.get("resource_id"),
                expected_bucket_owner=expected_account_id,
                s3_client=s3_client,
            )

        else:
            if not expected_subscription_id:
                return {
                    "status": "BLOCKED",
                    "mode": "Live",
                    "adapter": adapter,
                    "action_type": action_type,
                    "finding": finding,
                    "message": (
                        "The expected Azure subscription ID is "
                        "required for live Storage remediation."
                    ),
                }

            execution_result = (
                execute_azure_storage_account_hardening(
                    resource_id=target.get("resource_id"),
                    expected_subscription_id=(
                        expected_subscription_id
                    ),
                    storage_client=azure_storage_client,
                )
            )

    except ValueError as error:
        return {
            "status": "BLOCKED",
            "mode": "Live",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": str(error),
        }

    except Exception as error:
        provider = (
            "S3"
            if adapter == "S3_BLOCK_PUBLIC_ACCESS"
            else "Azure Storage"
        )

        return {
            "status": "FAILED",
            "mode": "Live",
            "adapter": adapter,
            "action_type": action_type,
            "finding": finding,
            "message": (
                f"Live {provider} remediation failed: {error}"
            ),
        }

    return {
        **execution_result,
        "mode": "Live",
        "action_type": action_type,
        "finding": finding,
    }


def get_adapter_for_action(action_type):
    return SUPPORTED_ACTIONS.get(
        action_type,
        "NO_APPROVED_ADAPTER",
    )


def build_execution_plan(action_type, finding):
    target = extract_resource_target(
        action_type=action_type,
        finding=finding,
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
        "live_execution_enabled": (
            adapter in LIVE_ENABLED_ADAPTERS
        ),
        "message": (
            "Dry-run execution plan created. "
            "No cloud resource changes were performed."
        ),
    }


def get_adapter_readiness_matrix():
    return [
        {
            "Adapter": "IAM_REVIEW",
            "Action Type": (
                "Generate IAM MFA and Access Key Review Task"
            ),
            "Resource Type": "IAM_USER",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Simulation Only",
        },
        {
            "Adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "Action Type": (
                "Generate S3 Exposure Remediation Task"
            ),
            "Resource Type": "S3_BUCKET",
            "Simulation Ready": True,
            "Live Execution": "Guarded",
            "Approval Required": True,
            "Readiness": "Controlled Testing",
        },
        {
            "Adapter": "AZURE_STORAGE_HARDENING",
            "Action Type": (
                "Generate Azure Storage Hardening Task"
            ),
            "Resource Type": "AZURE_STORAGE_ACCOUNT",
            "Simulation Ready": True,
            "Live Execution": "Guarded",
            "Approval Required": True,
            "Readiness": "Controlled Testing",
        },
        {
            "Adapter": "INCIDENT_RESPONSE_TASK",
            "Action Type": (
                "Generate Incident Response Investigation Task"
            ),
            "Resource Type": "SECURITY_INCIDENT",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only",
        },
        {
            "Adapter": "CSPM_REMEDIATION_TASK",
            "Action Type": (
                "Generate Cloud Security Posture Remediation Task"
            ),
            "Resource Type": "CSPM_FINDING",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only",
        },
        {
            "Adapter": "MONITORING_REVIEW_TASK",
            "Action Type": "Generate Monitoring Review Task",
            "Resource Type": "MONITORING_FINDING",
            "Simulation Ready": True,
            "Live Execution": "Blocked",
            "Approval Required": True,
            "Readiness": "Workflow Only",
        },
    ]
