def extract_resource_target(action_type, finding):
    finding_text = str(finding)

    if action_type == "Generate S3 Exposure Remediation Task":
        bucket_name = finding_text.replace("S3 Risk - ", "").strip()

        return {
            "resource_type": "S3_BUCKET",
            "resource_id": bucket_name,
            "supported": bool(bucket_name)
        }

    if action_type == "Generate IAM MFA and Access Key Review Task":
        username = finding_text.replace("IAM Risk - ", "").strip()

        return {
            "resource_type": "IAM_USER",
            "resource_id": username,
            "supported": bool(username)
        }

    if action_type == "Generate Incident Response Investigation Task":
        return {
            "resource_type": "SECURITY_INCIDENT",
            "resource_id": finding_text,
            "supported": True
        }

    if action_type == "Generate Cloud Security Posture Remediation Task":
        return {
            "resource_type": "CSPM_FINDING",
            "resource_id": finding_text,
            "supported": True
        }

    return {
        "resource_type": "MONITORING_FINDING",
        "resource_id": finding_text,
        "supported": True
    }
