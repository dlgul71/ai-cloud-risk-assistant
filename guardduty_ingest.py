import boto3


def get_guardduty_findings():

    findings_list = []

    try:

        gd = boto3.client("guardduty")

        detectors = gd.list_detectors()["DetectorIds"]

        if not detectors:
            return []

        detector_id = detectors[0]

        findings_response = gd.list_findings(
            DetectorId=detector_id,
            MaxResults=20
        )

        finding_ids = findings_response.get("FindingIds", [])

        if not finding_ids:
            return []

        findings = gd.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )

        for finding in findings.get("Findings", []):

            findings_list.append({
                "Title": finding.get("Title"),
                "Severity": finding.get("Severity"),
                "Type": finding.get("Type"),
                "Resource": (
                    finding.get("Resource", {})
                    .get("ResourceType", "Unknown")
                ),
                "Region": finding.get("Region"),
            })

        return findings_list

    except Exception as e:

        print(f"GuardDuty ingest error: {e}")

        return []
