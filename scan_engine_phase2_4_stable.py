from datetime import datetime
from kev_lookup import fetch_cisa_kev
from db import init_db, save_findings


def enrich_with_kev(cve_id, base_score, kev_map):

    kev_match = kev_map.get(cve_id)

    if kev_match:
        return {
            "cve_id": cve_id,
            "kev_exploited": True,
            "kev_date_added": kev_match.get("date_added"),
            "kev_due_date": kev_match.get("due_date"),
            "known_ransomware": kev_match.get("known_ransomware"),
            "required_action": kev_match.get("required_action"),
            "risk_score": base_score + 50,
            "priority": "CRITICAL"
        }

    return {
        "cve_id": cve_id,
        "kev_exploited": False,
        "risk_score": base_score,
        "priority": "STANDARD"
    }


def run_scan():

    print("=" * 60)
    print("DGS SENTINEL AI SCAN ENGINE")
    print("=" * 60)

    print(f"Scan Time: {datetime.utcnow()}")

    kev_map = fetch_cisa_kev()

    sample_cves = [
        {
            "cve_id": "CVE-2021-44228",
            "base_score": 40
        },
        {
            "cve_id": "CVE-2023-1234",
            "base_score": 15
        }
    ]

    findings = []

    for item in sample_cves:

        result = enrich_with_kev(
            item["cve_id"],
            item["base_score"],
            kev_map
        )

        findings.append(result)

    print("\nSCAN RESULTS")
    print("-" * 60)

    for finding in findings:

        print(f"\nCVE: {finding['cve_id']}")
        print(f"Priority: {finding['priority']}")
        print(f"Risk Score: {finding['risk_score']}")
        print(f"KEV Exploited: {finding['kev_exploited']}")

        if finding["kev_exploited"]:
            print(f"Date Added: {finding['kev_date_added']}")
            print(f"Ransomware: {finding['known_ransomware']}")
            print(f"Required Action: {finding['required_action']}")

    init_db()
    save_findings(findings)

    print("\n[+] Findings saved to SQLite database")
    print("\nScan Completed")

    return findings


if __name__ == "__main__":
    run_scan()
