from asset_db import get_assets
from securityhub_ingest import get_securityhub_findings


def correlate_securityhub_to_assets():
    assets = get_assets()
    findings = get_securityhub_findings()

    correlated = []

    for asset in assets:
        asset_id = asset[0]
        matches = []

        for finding in findings:
            resource = finding.get("Resource", "")

            if asset_id in resource:
                matches.append(finding)

        correlated.append({
            "asset_id": asset_id,
            "asset_type": asset[1],
            "account_id": asset[2],
            "region": asset[3],
            "risk_score": asset[6],
            "securityhub_findings": len(matches),
            "matched_findings": matches
        })

    return correlated


if __name__ == "__main__":
    results = correlate_securityhub_to_assets()

    for item in results:
        print(item)
