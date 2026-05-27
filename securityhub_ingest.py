import boto3


def get_securityhub_findings():

    findings_list = []

    try:

        client = boto3.client("securityhub")

        response = client.get_findings(
            MaxResults=20
        )

        findings = response.get("Findings", [])

        for finding in findings:

            findings_list.append({
                "Title": finding.get("Title"),
                "Severity": finding.get("Severity", {}).get("Label"),
                "Resource": (
                    finding.get("Resources", [{}])[0]
                    .get("Id", "Unknown")
                ),
                "Compliance": (
                    finding.get("Compliance", {})
                    .get("Status", "UNKNOWN")
                ),
                "Record State": finding.get("RecordState"),
            })

        return findings_list

    except Exception as e:

        print(f"Security Hub error: {e}")

        return []
