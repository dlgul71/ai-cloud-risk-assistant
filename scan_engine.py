from datetime import datetime, UTC

from db import init_db, save_findings
from ec2_ingest import get_ec2_assets
from iam_ingest import get_iam_risk_findings
from s3_ingest import get_s3_exposure_findings
from securityhub_ingest import get_securityhub_findings
from guardduty_ingest import get_guardduty_findings
from remediation_engine import generate_remediation_plan
from remediation_db import save_remediation_items
from remediation_execution import create_actions_from_remediation_plan


def priority_to_score(priority):
    priority = str(priority).upper()

    if priority == "CRITICAL":
        return 90
    if priority == "HIGH":
        return 75
    if priority == "MEDIUM" or priority == "MODERATE":
        return 50
    if priority == "LOW":
        return 20

    return 10


def normalize_securityhub_findings(findings):
    normalized = []

    for finding in findings:
        severity = finding.get("Severity", "UNKNOWN")
        score = priority_to_score(severity)

        normalized.append({
            "cve_id": finding.get("Title", "SecurityHub Finding"),
            "kev_exploited": False,
            "known_ransomware": "Unknown",
            "required_action": "Review Security Hub finding and remediate per SLA.",
            "risk_score": score,
            "priority": "CRITICAL" if score >= 90 else "HIGH" if score >= 75 else "STANDARD"
        })

    return normalized


def normalize_guardduty_findings(findings):
    normalized = []

    for finding in findings:
        severity = finding.get("Severity", 0)

        try:
            severity_value = float(severity)
        except Exception:
            severity_value = 0

        if severity_value >= 7:
            priority = "CRITICAL"
            score = 90
        elif severity_value >= 4:
            priority = "HIGH"
            score = 75
        else:
            priority = "STANDARD"
            score = 40

        normalized.append({
            "cve_id": finding.get("Title", "GuardDuty Finding"),
            "kev_exploited": False,
            "known_ransomware": "Unknown",
            "required_action": "Investigate GuardDuty finding and validate threat activity.",
            "risk_score": score,
            "priority": priority
        })

    return normalized


def normalize_iam_findings(findings):
    normalized = []

    for finding in findings:
        risk = finding.get("Risk", "LOW")
        score = priority_to_score(risk)

        normalized.append({
            "cve_id": f"IAM Risk - {finding.get('User', 'Unknown User')}",
            "kev_exploited": False,
            "known_ransomware": "Unknown",
            "required_action": "Enable MFA, review access keys, and rotate stale credentials.",
            "risk_score": score,
            "priority": "HIGH" if score >= 75 else "STANDARD"
        })

    return normalized


def normalize_s3_findings(findings):
    normalized = []

    for finding in findings:
        risk = finding.get("Risk", "LOW")
        score = priority_to_score(risk)

        normalized.append({
            "cve_id": f"S3 Risk - {finding.get('Bucket', 'Unknown Bucket')}",
            "kev_exploited": False,
            "known_ransomware": "Unknown",
            "required_action": "Review S3 public access block, bucket policy, ACLs, and encryption.",
            "risk_score": score,
            "priority": "HIGH" if score >= 75 else "STANDARD"
        })

    return normalized


def run_scan():

    print("=" * 60)
    print("DGS SENTINEL AI REAL AWS SCAN ENGINE")
    print("=" * 60)

    print(f"Scan Time: {datetime.now(UTC)}")

    ec2_assets = get_ec2_assets()
    iam_findings = get_iam_risk_findings()
    s3_findings = get_s3_exposure_findings()
    securityhub_findings = get_securityhub_findings()
    guardduty_findings = get_guardduty_findings()

    findings = []
    findings.extend(normalize_iam_findings(iam_findings))
    findings.extend(normalize_s3_findings(s3_findings))
    findings.extend(normalize_securityhub_findings(securityhub_findings))
    findings.extend(normalize_guardduty_findings(guardduty_findings))

    remediation_plan = generate_remediation_plan(findings)
    save_remediation_items(remediation_plan)

    execution_actions = create_actions_from_remediation_plan(
        remediation_plan
    )

    print(f"\n[+] Execution actions created: {len(execution_actions)}")

    print("\nREMEDIATION PLAN")
    print("-" * 60)

    for item in remediation_plan[:10]:
        print(f"{item.get('priority')} | {item.get('category')} | {item.get('finding')}")
        print(f"Recommendation: {item.get('recommendation')}")

    print("\nSCAN SUMMARY")
    print("-" * 60)
    print(f"EC2 Assets: {len(ec2_assets)}")
    print(f"IAM Findings: {len(iam_findings)}")
    print(f"S3 Findings: {len(s3_findings)}")
    print(f"Security Hub Findings: {len(securityhub_findings)}")
    print(f"GuardDuty Findings: {len(guardduty_findings)}")
    print(f"Normalized Findings Saved: {len(findings)}")

    init_db()
    save_findings(findings)

    print("\n[+] Real AWS findings saved to SQLite database")
    print("\nScan Completed")

    return findings


if __name__ == "__main__":
    run_scan()
