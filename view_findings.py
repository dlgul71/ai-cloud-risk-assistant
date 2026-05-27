from db import get_all_findings


rows = get_all_findings()

print("\nDGS Sentinel AI - Saved Findings")
print("=" * 60)

if not rows:
    print("No findings found.")
else:
    for row in rows:
        print("\nScan Time:", row[0])
        print("CVE ID:", row[1])
        print("Priority:", row[2])
        print("Risk Score:", row[3])
        print("KEV Exploited:", row[4])
        print("Known Ransomware:", row[5])
        print("Required Action:", row[6])
