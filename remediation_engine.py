from datetime import datetime, UTC


def generate_remediation_recommendation(finding):
    title = str(finding.get("cve_id", finding.get("Title", ""))).lower()
    priority = str(finding.get("priority", finding.get("Priority", "STANDARD"))).upper()
    risk_score = finding.get("risk_score", finding.get("Risk Score", 0))

    if "iam risk" in title or "mfa" in title:
        return {
            "created_at": str(datetime.now(UTC)),
            "category": "Identity & Access",
            "priority": (
                "CRITICAL"
                if priority == "CRITICAL" or risk_score >= 90
                else "HIGH"
            ),
            "finding": finding.get("cve_id", "IAM Risk"),
            "recommendation": "Enable MFA, review access keys, rotate stale credentials, and enforce least privilege.",
            "owner": "IAM / Cloud Security",
            "status": "Open",
            "risk_score": risk_score
        }

    if "s3 risk" in title or "bucket" in title:
        return {
            "created_at": str(datetime.now(UTC)),
            "category": "Data Exposure",
            "priority": (
                "CRITICAL"
                if priority == "CRITICAL" or risk_score >= 90
                else "HIGH"
            ),
            "finding": finding.get("cve_id", "S3 Exposure Risk"),
            "recommendation": "Enable S3 Block Public Access, review bucket policy/ACLs, and confirm encryption is enabled.",
            "owner": "Cloud Security / Storage Owner",
            "status": "Open",
            "risk_score": risk_score
        }

    if "guardduty" in title:
        return {
            "created_at": str(datetime.now(UTC)),
            "category": "Threat Detection",
            "priority": priority,
            "finding": finding.get("cve_id", "GuardDuty Finding"),
            "recommendation": "Investigate GuardDuty finding, validate affected resource, review CloudTrail, and isolate if active compromise is suspected.",
            "owner": "SOC / Incident Response",
            "status": "Open",
            "risk_score": risk_score
        }

    if priority in ["CRITICAL", "HIGH"] or risk_score >= 75:
        return {
            "created_at": str(datetime.now(UTC)),
            "category": "Security Posture",
            "priority": priority,
            "finding": finding.get("cve_id", "High Risk Finding"),
            "recommendation": "Review affected resource, validate exposure, remediate per SLA, and document evidence of closure.",
            "owner": "Cloud Security",
            "status": "Open",
            "risk_score": risk_score
        }

    return {
        "created_at": str(datetime.now(UTC)),
        "category": "Monitoring",
        "priority": "STANDARD",
        "finding": finding.get("cve_id", "Standard Finding"),
        "recommendation": "Monitor finding and remediate during the normal maintenance cycle.",
        "owner": "Security Operations",
        "status": "Open",
        "risk_score": risk_score
    }


def generate_remediation_plan(findings):
    return [
        generate_remediation_recommendation(finding)
        for finding in findings
    ]
