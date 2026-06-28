"""Manual cross-account AWS connection diagnostic.

Usage:
    export DGS_TEST_ROLE_ARN="arn:aws:iam::<account>:role/<role>"
    python -m scripts.check_client_connection
"""

from __future__ import annotations

import os

from client_accounts import client_boto3_client


def main() -> int:
    role_arn = os.getenv("DGS_TEST_ROLE_ARN")

    if not role_arn:
        print(
            "DGS_TEST_ROLE_ARN is not configured. "
            "No AWS request was performed."
        )
        return 2

    ec2_client = client_boto3_client(
        "ec2",
        role_arn,
    )

    if ec2_client:
        print("Connection successful")
        return 0

    print("Connection failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
