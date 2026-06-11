from pathlib import Path

from asset_db import get_assets
from remediation_db import get_remediation_items
from remediation_execution import get_execution_actions
from caasm_snapshot_engine import load_caasm_snapshots


def build_security_context():
    assets = get_assets()
    remediation_items = get_remediation_items()
    execution_actions = get_execution_actions()
    caasm_snapshots = load_caasm_snapshots()

    latest_caasm_snapshot = (
        caasm_snapshots[-1]
        if caasm_snapshots
        else {}
    )

    asset_rows = []

    for asset in assets:
        asset_rows.append({
            "asset_id": asset[0],
            "asset_type": asset[1],
            "account_id": asset[2],
            "region": asset[3],
            "hostname": asset[4],
            "private_ip": asset[5],
            "public_ip": asset[6],
            "state": asset[7],
            "risk_score": asset[8],
            "last_scan": asset[9]
        })

    remediation_rows = []

    for item in remediation_items:
        remediation_rows.append({
            "id": item[0],
            "created_at": item[1],
            "category": item[2],
            "priority": item[3],
            "finding": item[4],
            "recommendation": item[5],
            "owner": item[6],
            "status": item[7],
            "risk_score": item[8]
        })

    execution_rows = []

    for action in execution_actions:
        execution_rows.append({
            "id": action[0],
            "created_at": action[1],
            "finding": action[2],
            "action_type": action[3],
            "priority": action[4],
            "approval_status": action[5],
            "execution_status": action[6],
            "execution_mode": action[7],
            "notes": action[8]
        })

    return {
        "assets": asset_rows,
        "remediation_items": remediation_rows,
        "execution_actions": execution_rows,
        "latest_caasm_snapshot": latest_caasm_snapshot,
        "caasm_snapshot_count": len(caasm_snapshots)
    }


def calculate_analyst_metrics(context):
    assets = context.get("assets", [])
    remediation_items = context.get("remediation_items", [])
    execution_actions = context.get("execution_actions", [])

    critical_remediation = [
        item
        for item in remediation_items
        if item.get("priority") == "CRITICAL"
    ]

    high_remediation = [
        item
        for item in remediation_items
        if item.get("priority") == "HIGH"
    ]

    open_remediation = [
        item
        for item in remediation_items
        if item.get("status") == "Open"
    ]

    completed_actions = [
        item
        for item in execution_actions
        if item.get("execution_status") == "Completed"
    ]

    pending_actions = [
        item
        for item in execution_actions
        if item.get("approval_status") == "Pending Approval"
    ]

    public_assets = [
        asset
        for asset in assets
        if asset.get("public_ip")
    ]

    latest_caasm_snapshot = context.get(
        "latest_caasm_snapshot",
        {}
    )

    caasm_metrics = latest_caasm_snapshot.get(
        "metrics",
        {}
    )

    identity_metrics = latest_caasm_snapshot.get(
        "identity_governance_metrics",
        {}
    )

    coverage_metrics = latest_caasm_snapshot.get(
        "coverage_gap_metrics",
        {}
    )

    return {
        "Total Assets": len(assets),
        "Public Assets": len(public_assets),
        "Critical Remediation Items": len(critical_remediation),
        "High Remediation Items": len(high_remediation),
        "Open Remediation Items": len(open_remediation),
        "Pending Execution Approvals": len(pending_actions),
        "Completed Simulation Actions": len(completed_actions),
        "CAASM Score": caasm_metrics.get("CAASM Score", 0),
        "Asset Coverage %": caasm_metrics.get("Asset Coverage %", 0),
        "MFA Coverage %": caasm_metrics.get("MFA Coverage %", 0),
        "Orphaned Accounts": identity_metrics.get("Orphaned Accounts", 0),
        "Privileged Without MFA": identity_metrics.get("Privileged Without MFA", 0),
        "Critical Coverage Gaps": coverage_metrics.get("Critical Coverage Gaps", 0)
    }


def get_top_remediation_items(context, limit=10):
    remediation_items = context.get(
        "remediation_items",
        []
    )

    return sorted(
        remediation_items,
        key=lambda item: item.get("risk_score", 0),
        reverse=True
    )[:limit]


def generate_local_analyst_response(question):
    context = build_security_context()
    metrics = calculate_analyst_metrics(context)
    top_items = get_top_remediation_items(context)

    question_text = str(question).lower()

    lines = [
        "DGS Sentinel AI Security Analyst",
        "",
        "Executive Security Summary",
        "-" * 50
    ]

    for key, value in metrics.items():
        lines.append(f"{key}: {value}")

    if (
        "top risk" in question_text
        or "fix first" in question_text
        or "priority" in question_text
    ):
        lines.extend([
            "",
            "Top Remediation Priorities",
            "-" * 50
        ])

        for item in top_items[:10]:
            lines.append(
                f"{item.get('priority')} | "
                f"{item.get('category')} | "
                f"{item.get('finding')} | "
                f"Risk Score: {item.get('risk_score')}"
            )

            lines.append(
                f"Recommendation: "
                f"{item.get('recommendation')}"
            )

    elif "caasm" in question_text or "identity" in question_text:
        lines.extend([
            "",
            "CAASM and Identity Governance Summary",
            "-" * 50,
            f"CAASM Score: {metrics.get('CAASM Score')}",
            f"Asset Coverage %: {metrics.get('Asset Coverage %')}",
            f"MFA Coverage %: {metrics.get('MFA Coverage %')}",
            f"Orphaned Accounts: {metrics.get('Orphaned Accounts')}",
            f"Privileged Without MFA: {metrics.get('Privileged Without MFA')}",
            f"Critical Coverage Gaps: {metrics.get('Critical Coverage Gaps')}"
        ])

    else:
        lines.extend([
            "",
            "Recommended Focus",
            "-" * 50,
            "1. Review critical and high-risk remediation items.",
            "2. Resolve pending execution approvals.",
            "3. Address identity-governance exceptions.",
            "4. Improve missing security-tool coverage.",
            "5. Run recurring scans and compare historical trends."
        ])

    lines.extend([
        "",
        "Note: This response is generated only from saved DGS Sentinel AI platform data."
    ])

    return "\n".join(lines)


if __name__ == "__main__":
    question = input("Ask Sentinel AI: ")

    print()
    print(generate_local_analyst_response(question))
