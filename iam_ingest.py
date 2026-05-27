import boto3
from datetime import datetime, timezone


def get_iam_risk_findings():

    findings = []

    try:

        iam = boto3.client("iam")

        users = iam.list_users()["Users"]

        for user in users:

            username = user["UserName"]

            # ====================================================
            # MFA STATUS
            # ====================================================

            mfa_devices = iam.list_mfa_devices(
                UserName=username
            )["MFADevices"]

            mfa_enabled = len(mfa_devices) > 0

            # ====================================================
            # ACCESS KEYS
            # ====================================================

            access_keys = iam.list_access_keys(
                UserName=username
            )["AccessKeyMetadata"]

            stale_keys = 0

            for key in access_keys:

                create_date = key["CreateDate"]

                age_days = (
                    datetime.now(timezone.utc) - create_date
                ).days

                if age_days > 90:
                    stale_keys += 1

            findings.append({
                "User": username,
                "MFA Enabled": mfa_enabled,
                "Access Keys": len(access_keys),
                "Stale Keys": stale_keys,
                "Risk": (
                    "HIGH"
                    if not mfa_enabled
                    else "MODERATE"
                    if stale_keys > 0
                    else "LOW"
                )
            })

        return findings

    except Exception as e:

        print(f"IAM ingest error: {e}")

        return []
