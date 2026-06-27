from datetime import datetime, UTC

from botocore.exceptions import ClientError

from client_accounts import client_boto3_client
from asset_db import init_asset_db, save_asset
from risk_engine import calculate_asset_risk
from remediation_engine import generate_remediation_plan
from remediation_db import save_remediation_items


REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
]


def aws_error_text(error):
    if isinstance(error, ClientError):
        error_data = error.response.get("Error", {})

        return (
            f"{error_data.get('Code', 'AWS_ERROR')}: "
            f"{error_data.get('Message', str(error))}"
        )

    return str(error)


def collect_paginated(client, operation_name, result_key, **kwargs):
    if client.can_paginate(operation_name):
        paginator = client.get_paginator(operation_name)
        results = []

        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))

        return results

    response = getattr(client, operation_name)(**kwargs)

    return response.get(result_key, [])


def test_client_identity(role_arn):
    sts = client_boto3_client("sts", role_arn)

    if not sts:
        return {
            "status": "FAILED",
            "message": "Could not assume client role.",
        }

    try:
        identity = sts.get_caller_identity()

        return {
            "status": "SUCCESS",
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
            "scan_time": str(datetime.now(UTC)),
        }

    except Exception as error:
        return {
            "status": "FAILED",
            "message": aws_error_text(error),
        }


def scan_client_ec2(role_arn, region_name):
    ec2 = client_boto3_client(
        "ec2",
        role_arn,
        region_name,
    )

    if not ec2:
        raise RuntimeError(
            f"Could not create EC2 client for {region_name}."
        )

    instances = []
    response = ec2.describe_instances()

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instances.append({
                "instance_id": instance.get("InstanceId"),
                "state": instance.get("State", {}).get("Name"),
                "instance_type": instance.get("InstanceType"),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
                "region": region_name,
            })

    return instances


def scan_client_iam(role_arn):
    iam = client_boto3_client("iam", role_arn)

    if not iam:
        return [], [
            "IAM: Could not create assumed-role IAM client."
        ]

    scan_errors = []
    iam_users = []

    try:
        users = collect_paginated(
            iam,
            "list_users",
            "Users",
        )

    except Exception as error:
        return [], [
            f"IAM list_users failed: {aws_error_text(error)}"
        ]

    for user in users:
        user_name = user.get("UserName", "Unknown")

        mfa_enabled = None
        active_access_keys = None

        try:
            mfa_devices = collect_paginated(
                iam,
                "list_mfa_devices",
                "MFADevices",
                UserName=user_name,
            )

            mfa_enabled = bool(mfa_devices)

        except Exception as error:
            scan_errors.append(
                f"IAM MFA check failed for {user_name}: "
                f"{aws_error_text(error)}"
            )

        try:
            access_keys = collect_paginated(
                iam,
                "list_access_keys",
                "AccessKeyMetadata",
                UserName=user_name,
            )

            active_access_keys = len([
                key
                for key in access_keys
                if str(key.get("Status", "")).lower() == "active"
            ])

        except Exception as error:
            scan_errors.append(
                f"IAM access-key check failed for {user_name}: "
                f"{aws_error_text(error)}"
            )

        risk_score = 10

        if mfa_enabled is False:
            risk_score += 40
        elif mfa_enabled is None:
            risk_score += 10

        if active_access_keys is None:
            risk_score += 10
        elif active_access_keys > 0:
            risk_score += 30

            if active_access_keys > 1:
                risk_score += 10

        risk_score = min(risk_score, 100)

        mfa_label = (
            "Enabled"
            if mfa_enabled is True
            else "Missing"
            if mfa_enabled is False
            else "Unknown"
        )

        key_label = (
            active_access_keys
            if active_access_keys is not None
            else "Unknown"
        )

        iam_users.append({
            "user_name": user_name,
            "mfa_enabled": mfa_enabled,
            "active_access_keys": active_access_keys,
            "create_date": str(user.get("CreateDate", "")),
            "risk_score": risk_score,
            "state": (
                f"MFA: {mfa_label}; "
                f"Active Keys: {key_label}"
            ),
        })

    return iam_users, scan_errors


def scan_client_s3(role_arn):
    s3 = client_boto3_client(
        "s3",
        role_arn,
        "us-east-1",
    )

    if not s3:
        return [], [
            "S3: Could not create assumed-role S3 client."
        ]

    scan_errors = []
    s3_buckets = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])

    except Exception as error:
        return [], [
            f"S3 list_buckets failed: {aws_error_text(error)}"
        ]

    for bucket in buckets:
        bucket_name = bucket.get("Name", "Unknown")

        region = "Unknown"
        public_access_block = None
        policy_public = None
        encryption_enabled = None

        try:
            location_response = s3.get_bucket_location(
                Bucket=bucket_name
            )

            region = (
                location_response.get("LocationConstraint")
                or "us-east-1"
            )

            if region == "EU":
                region = "eu-west-1"

        except Exception as error:
            scan_errors.append(
                f"S3 location check failed for {bucket_name}: "
                f"{aws_error_text(error)}"
            )

        try:
            access_response = s3.get_public_access_block(
                Bucket=bucket_name
            )

            configuration = access_response.get(
                "PublicAccessBlockConfiguration",
                {},
            )

            public_access_block = all([
                configuration.get("BlockPublicAcls", False),
                configuration.get("IgnorePublicAcls", False),
                configuration.get("BlockPublicPolicy", False),
                configuration.get("RestrictPublicBuckets", False),
            ])

        except ClientError as error:
            error_code = error.response.get(
                "Error",
                {},
            ).get("Code")

            if error_code in {
                "NoSuchPublicAccessBlock",
                "NoSuchPublicAccessBlockConfiguration",
            }:
                public_access_block = False
            else:
                scan_errors.append(
                    f"S3 public-access-block check failed for "
                    f"{bucket_name}: {aws_error_text(error)}"
                )

        except Exception as error:
            scan_errors.append(
                f"S3 public-access-block check failed for "
                f"{bucket_name}: {aws_error_text(error)}"
            )

        try:
            policy_response = s3.get_bucket_policy_status(
                Bucket=bucket_name
            )

            policy_public = bool(
                policy_response.get(
                    "PolicyStatus",
                    {},
                ).get("IsPublic", False)
            )

        except ClientError as error:
            error_code = error.response.get(
                "Error",
                {},
            ).get("Code")

            if error_code == "NoSuchBucketPolicy":
                policy_public = False
            else:
                scan_errors.append(
                    f"S3 policy-status check failed for "
                    f"{bucket_name}: {aws_error_text(error)}"
                )

        except Exception as error:
            scan_errors.append(
                f"S3 policy-status check failed for "
                f"{bucket_name}: {aws_error_text(error)}"
            )

        try:
            s3.get_bucket_encryption(
                Bucket=bucket_name
            )

            encryption_enabled = True

        except ClientError as error:
            error_code = error.response.get(
                "Error",
                {},
            ).get("Code")

            if error_code == (
                "ServerSideEncryptionConfigurationNotFoundError"
            ):
                encryption_enabled = False
            else:
                scan_errors.append(
                    f"S3 encryption check failed for "
                    f"{bucket_name}: {aws_error_text(error)}"
                )

        except Exception as error:
            scan_errors.append(
                f"S3 encryption check failed for "
                f"{bucket_name}: {aws_error_text(error)}"
            )

        risk_score = 10

        if policy_public is True:
            risk_score = 90
        else:
            if public_access_block is False:
                risk_score += 40
            elif public_access_block is None:
                risk_score += 10

            if encryption_enabled is False:
                risk_score += 25
            elif encryption_enabled is None:
                risk_score += 10

        risk_score = min(risk_score, 100)

        s3_buckets.append({
            "bucket_name": bucket_name,
            "region": region,
            "public_access_block": public_access_block,
            "policy_public": policy_public,
            "encryption_enabled": encryption_enabled,
            "risk_score": risk_score,
            "state": (
                f"Public Access Block: {public_access_block}; "
                f"Policy Public: {policy_public}; "
                f"Encryption: {encryption_enabled}"
            ),
        })

    return s3_buckets, scan_errors


def run_client_scan(role_arn, client_name=None):
    print("=" * 60)
    print("DGS SENTINEL AI PHASE 13 CLIENT AWS SCAN")
    print("=" * 60)

    identity = test_client_identity(role_arn)
    print(identity)

    if identity.get("status") != "SUCCESS":
        return {
            "identity": identity,
            "regions_scanned": [],
            "ec2_instances": [],
            "iam_users": [],
            "s3_buckets": [],
            "ec2_count": 0,
            "iam_count": 0,
            "s3_count": 0,
            "scan_errors": [
                identity.get(
                    "message",
                    "Unable to assume client role.",
                )
            ],
        }

    init_asset_db()

    account_id = str(identity.get("account"))
    scan_time = str(datetime.now(UTC))

    scan_errors = []
    ec2_instances = []

    for region in REGIONS:
        print(f"Scanning EC2 in region: {region}")

        try:
            region_instances = scan_client_ec2(
                role_arn,
                region,
            )

            ec2_instances.extend(region_instances)

        except Exception as error:
            scan_errors.append(
                f"EC2 scan failed in {region}: "
                f"{aws_error_text(error)}"
            )

    for instance in ec2_instances:
        asset_record = {
            "asset_id": instance.get("instance_id"),
            "asset_type": "EC2",
            "account_id": account_id,
            "region": instance.get("region"),
            "hostname": instance.get("instance_id"),
            "ip_address": instance.get("private_ip"),
            "public_ip": instance.get("public_ip"),
            "state": instance.get("state"),
            "last_scan": scan_time,
        }

        asset_record["risk_score"] = calculate_asset_risk(
            asset_record
        )

        save_asset(asset_record)

    print("Scanning IAM users")

    iam_users, iam_errors = scan_client_iam(role_arn)
    scan_errors.extend(iam_errors)

    for iam_user in iam_users:
        user_name = iam_user.get("user_name", "Unknown")

        save_asset({
            "asset_id": f"{account_id}:iam:{user_name}",
            "asset_type": "IAM User",
            "account_id": account_id,
            "region": "global",
            "hostname": user_name,
            "ip_address": None,
            "public_ip": None,
            "state": iam_user.get("state"),
            "risk_score": iam_user.get("risk_score", 0),
            "last_scan": scan_time,
        })

    print("Scanning S3 buckets")

    s3_buckets, s3_errors = scan_client_s3(role_arn)
    scan_errors.extend(s3_errors)

    for s3_bucket in s3_buckets:
        bucket_name = s3_bucket.get(
            "bucket_name",
            "Unknown",
        )

        save_asset({
            "asset_id": f"{account_id}:s3:{bucket_name}",
            "asset_type": "S3 Bucket",
            "account_id": account_id,
            "region": s3_bucket.get("region"),
            "hostname": bucket_name,
            "ip_address": None,
            "public_ip": (
                "PUBLIC"
                if s3_bucket.get("policy_public") is True
                else None
            ),
            "state": s3_bucket.get("state"),
            "risk_score": s3_bucket.get("risk_score", 0),
            "last_scan": scan_time,
        })

    client_findings = []

    for iam_user in iam_users:
        user_name = iam_user.get(
            "user_name",
            "Unknown"
        )

        if iam_user.get("mfa_enabled") is False:
            client_findings.append({
                "cve_id": (
                    f"IAM Risk - {user_name} - MFA Missing"
                ),
                "priority": "HIGH",
                "risk_score": 75
            })

        active_access_keys = iam_user.get(
            "active_access_keys"
        )

        if (
            isinstance(active_access_keys, int)
            and active_access_keys > 0
        ):
            multiple_keys = active_access_keys > 1

            client_findings.append({
                "cve_id": (
                    f"IAM Risk - {user_name} - "
                    f"{active_access_keys} Active Access Key"
                    f"{'s' if multiple_keys else ''}"
                ),
                "priority": (
                    "CRITICAL"
                    if multiple_keys
                    else "HIGH"
                ),
                "risk_score": (
                    90
                    if multiple_keys
                    else 75
                )
            })

    for s3_bucket in s3_buckets:
        bucket_name = s3_bucket.get(
            "bucket_name",
            "Unknown"
        )

        if (
            s3_bucket.get(
                "public_access_block"
            ) is False
        ):
            client_findings.append({
                "cve_id": (
                    f"S3 Risk - {bucket_name} - "
                    "Public Access Block Disabled"
                ),
                "priority": "HIGH",
                "risk_score": 75
            })

        if s3_bucket.get("policy_public") is True:
            client_findings.append({
                "cve_id": (
                    f"S3 Risk - {bucket_name} - "
                    "Bucket Policy Is Public"
                ),
                "priority": "CRITICAL",
                "risk_score": 95
            })

        if (
            s3_bucket.get(
                "encryption_enabled"
            ) is False
        ):
            client_findings.append({
                "cve_id": (
                    f"S3 Risk - {bucket_name} - "
                    "Default Encryption Missing"
                ),
                "priority": "HIGH",
                "risk_score": 75
            })

    remediation_plan = generate_remediation_plan(
        client_findings
    )

    if remediation_plan:
        save_remediation_items(
            remediation_plan,
            aws_account_id=account_id,
            client_name=(
                client_name
                or f"AWS Account {account_id}"
            )
        )

    return {
        "identity": identity,
        "regions_scanned": REGIONS,
        "ec2_instances": ec2_instances,
        "iam_users": iam_users,
        "s3_buckets": s3_buckets,
        "ec2_count": len(ec2_instances),
        "iam_count": len(iam_users),
        "s3_count": len(s3_buckets),
        "remediation_findings": client_findings,
        "remediation_plan": remediation_plan,
        "remediation_count": len(remediation_plan),
        "scan_errors": scan_errors,
    }
