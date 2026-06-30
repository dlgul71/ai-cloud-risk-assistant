from datetime import datetime, UTC

from botocore.exceptions import ClientError

from client_accounts import client_boto3_client
from asset_db import init_asset_db, save_asset
from risk_engine import calculate_asset_risk
from remediation_engine import generate_remediation_plan
from remediation_db import save_remediation_items
from remediation_execution import create_actions_from_remediation_plan
from client_detection_store import save_client_scan_summary


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



def scan_client_securityhub(role_arn):
    findings = []
    scan_errors = []
    enabled_regions = []

    for region in REGIONS:
        client = client_boto3_client(
            "securityhub",
            role_arn,
            region
        )

        if not client:
            scan_errors.append(
                f"Security Hub client unavailable in {region}."
            )
            continue

        try:
            client.describe_hub()
            enabled_regions.append(region)

        except ClientError as error:
            error_code = error.response.get(
                "Error",
                {}
            ).get("Code")

            if error_code in {
                "InvalidAccessException",
                "ResourceNotFoundException"
            }:
                continue

            scan_errors.append(
                f"Security Hub status check failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        except Exception as error:
            scan_errors.append(
                f"Security Hub status check failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        try:
            paginator = client.get_paginator(
                "get_findings"
            )

            item_count = 0

            for page in paginator.paginate(
                Filters={
                    "RecordState": [
                        {
                            "Value": "ACTIVE",
                            "Comparison": "EQUALS"
                        }
                    ]
                },
                PaginationConfig={
                    "MaxItems": 100
                }
            ):
                for finding in page.get(
                    "Findings",
                    []
                ):
                    resources = finding.get(
                        "Resources",
                        []
                    )

                    resource_id = (
                        resources[0].get(
                            "Id",
                            "Unknown"
                        )
                        if resources
                        else "Unknown"
                    )

                    findings.append({
                        "finding_id": finding.get("Id"),
                        "title": finding.get(
                            "Title",
                            "Security Hub Finding"
                        ),
                        "severity": finding.get(
                            "Severity",
                            {}
                        ).get(
                            "Label",
                            "UNKNOWN"
                        ),
                        "resource": resource_id,
                        "compliance": finding.get(
                            "Compliance",
                            {}
                        ).get(
                            "Status",
                            "UNKNOWN"
                        ),
                        "record_state": finding.get(
                            "RecordState",
                            "UNKNOWN"
                        ),
                        "region": region
                    })

                    item_count += 1

                    if item_count >= 100:
                        break

                if item_count >= 100:
                    break

        except Exception as error:
            scan_errors.append(
                f"Security Hub findings scan failed in {region}: "
                f"{aws_error_text(error)}"
            )

    if enabled_regions and scan_errors:
        status = "Partial"
    elif enabled_regions and findings:
        status = "Enabled"
    elif enabled_regions:
        status = "Enabled — no active findings"
    elif scan_errors:
        status = "Unavailable"
    else:
        status = "Not enabled"

    return findings, scan_errors, {
        "status": status,
        "enabled_regions": enabled_regions,
        "regions_checked": REGIONS
    }


def scan_client_guardduty(role_arn):
    findings = []
    scan_errors = []
    enabled_regions = []

    for region in REGIONS:
        client = client_boto3_client(
            "guardduty",
            role_arn,
            region
        )

        if not client:
            scan_errors.append(
                f"GuardDuty client unavailable in {region}."
            )
            continue

        try:
            detector_ids = client.list_detectors().get(
                "DetectorIds",
                []
            )

        except Exception as error:
            scan_errors.append(
                f"GuardDuty detector scan failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        if not detector_ids:
            continue

        enabled_regions.append(region)

        for detector_id in detector_ids:
            try:
                paginator = client.get_paginator(
                    "list_findings"
                )

                finding_ids = []

                for page in paginator.paginate(
                    DetectorId=detector_id,
                    PaginationConfig={
                        "MaxItems": 100
                    }
                ):
                    finding_ids.extend(
                        page.get(
                            "FindingIds",
                            []
                        )
                    )

                for start in range(
                    0,
                    len(finding_ids),
                    50
                ):
                    batch_ids = finding_ids[
                        start:start + 50
                    ]

                    if not batch_ids:
                        continue

                    response = client.get_findings(
                        DetectorId=detector_id,
                        FindingIds=batch_ids
                    )

                    for finding in response.get(
                        "Findings",
                        []
                    ):
                        findings.append({
                            "finding_id": finding.get("Id"),
                            "title": finding.get(
                                "Title",
                                "GuardDuty Finding"
                            ),
                            "severity": finding.get(
                                "Severity",
                                0
                            ),
                            "type": finding.get(
                                "Type",
                                "Unknown"
                            ),
                            "resource": finding.get(
                                "Resource",
                                {}
                            ).get(
                                "ResourceType",
                                "Unknown"
                            ),
                            "region": finding.get(
                                "Region",
                                region
                            )
                        })

            except Exception as error:
                scan_errors.append(
                    f"GuardDuty findings scan failed in {region}: "
                    f"{aws_error_text(error)}"
                )

    if enabled_regions and scan_errors:
        status = "Partial"
    elif enabled_regions and findings:
        status = "Enabled"
    elif enabled_regions:
        status = "Enabled — no findings"
    elif scan_errors:
        status = "Unavailable"
    else:
        status = "Not enabled"

    return findings, scan_errors, {
        "status": status,
        "enabled_regions": enabled_regions,
        "regions_checked": REGIONS
    }



def scan_client_config(role_arn):
    findings = []
    scan_errors = []
    enabled_regions = []
    stopped_regions = []
    total_rule_count = 0

    for region in REGIONS:
        client = client_boto3_client(
            "config",
            role_arn,
            region
        )

        if not client:
            scan_errors.append(
                f"AWS Config client unavailable in {region}."
            )
            continue

        try:
            recorders = client.describe_configuration_recorders().get(
                "ConfigurationRecorders",
                []
            )

            recorder_statuses = (
                client.describe_configuration_recorder_status().get(
                    "ConfigurationRecordersStatus",
                    []
                )
            )

        except ClientError as error:
            error_code = error.response.get(
                "Error",
                {}
            ).get("Code")

            if error_code in {
                "NoAvailableConfigurationRecorderException",
                "ResourceNotFoundException"
            }:
                continue

            scan_errors.append(
                f"AWS Config recorder check failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        except Exception as error:
            scan_errors.append(
                f"AWS Config recorder check failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        if not recorders:
            continue

        recorder_is_running = any(
            item.get("recording") is True
            for item in recorder_statuses
        )

        if recorder_is_running:
            enabled_regions.append(region)
        else:
            stopped_regions.append(region)

        try:
            config_rules = []
            next_token = None

            while True:
                request = {}

                if next_token:
                    request["NextToken"] = next_token

                response = client.describe_config_rules(
                    **request
                )

                config_rules.extend(
                    response.get("ConfigRules", [])
                )

                next_token = response.get("NextToken")

                if not next_token:
                    break

            total_rule_count += len(config_rules)

        except Exception as error:
            scan_errors.append(
                f"AWS Config rule inventory failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        try:
            noncompliant_rule_names = set()
            next_token = None

            while True:
                request = {
                    "ComplianceTypes": [
                        "NON_COMPLIANT"
                    ]
                }

                if next_token:
                    request["NextToken"] = next_token

                response = (
                    client.describe_compliance_by_config_rule(
                        **request
                    )
                )

                for item in response.get(
                    "ComplianceByConfigRules",
                    []
                ):
                    rule_name = item.get(
                        "ConfigRuleName"
                    )

                    compliance_type = item.get(
                        "Compliance",
                        {}
                    ).get(
                        "ComplianceType"
                    )

                    if (
                        rule_name
                        and compliance_type
                        == "NON_COMPLIANT"
                    ):
                        noncompliant_rule_names.add(
                            rule_name
                        )

                next_token = response.get("NextToken")

                if not next_token:
                    break

        except Exception as error:
            scan_errors.append(
                f"AWS Config compliance scan failed in {region}: "
                f"{aws_error_text(error)}"
            )
            continue

        rules_by_name = {
            rule.get("ConfigRuleName"): rule
            for rule in config_rules
            if rule.get("ConfigRuleName")
        }

        for rule_name in sorted(
            noncompliant_rule_names
        ):
            resource_count = 0
            sample_resources = []
            next_token = None
            details_available = True

            try:
                while True:
                    request = {
                        "ConfigRuleName": rule_name,
                        "ComplianceTypes": [
                            "NON_COMPLIANT"
                        ],
                        "Limit": 100
                    }

                    if next_token:
                        request["NextToken"] = next_token

                    response = (
                        client.get_compliance_details_by_config_rule(
                            **request
                        )
                    )

                    for result in response.get(
                        "EvaluationResults",
                        []
                    ):
                        qualifier = result.get(
                            "EvaluationResultIdentifier",
                            {}
                        ).get(
                            "EvaluationResultQualifier",
                            {}
                        )

                        resource_id = qualifier.get(
                            "ResourceId",
                            "Unknown"
                        )

                        resource_type = qualifier.get(
                            "ResourceType",
                            "Unknown"
                        )

                        resource_count += 1

                        if len(sample_resources) < 10:
                            sample_resources.append(
                                f"{resource_type}:"
                                f"{resource_id}"
                            )

                    next_token = response.get(
                        "NextToken"
                    )

                    if not next_token:
                        break

            except Exception as error:
                details_available = False

                scan_errors.append(
                    f"AWS Config resource details failed "
                    f"for {rule_name} in {region}: "
                    f"{aws_error_text(error)}"
                )

            rule = rules_by_name.get(
                rule_name,
                {}
            )

            findings.append({
                "rule_name": rule_name,
                "region": region,
                "compliance": "NON_COMPLIANT",
                "noncompliant_resource_count": (
                    resource_count
                    if details_available
                    else None
                ),
                "sample_resources": (
                    ", ".join(sample_resources)
                    if sample_resources
                    else "No resource sample available"
                ),
                "description": rule.get(
                    "Description",
                    ""
                ),
                "source_owner": rule.get(
                    "Source",
                    {}
                ).get(
                    "Owner",
                    "Unknown"
                )
            })

    noncompliant_resource_count = sum(
        item.get(
            "noncompliant_resource_count"
        ) or 0
        for item in findings
    )

    if enabled_regions and scan_errors:
        status = "Partial"
    elif enabled_regions and findings:
        status = "Enabled — noncompliance found"
    elif enabled_regions and total_rule_count:
        status = "Enabled — compliant"
    elif enabled_regions:
        status = "Enabled — no rules"
    elif stopped_regions:
        status = "Recorder stopped"
    elif scan_errors:
        status = "Unavailable"
    else:
        status = "Not enabled"

    service = {
        "status": status,
        "enabled_regions": enabled_regions,
        "stopped_regions": stopped_regions,
        "regions_checked": REGIONS,
        "rule_count": total_rule_count,
        "noncompliant_rule_count": len(findings),
        "noncompliant_resource_count": (
            noncompliant_resource_count
        )
    }

    return findings, scan_errors, service


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

    print("Scanning Security Hub")

    (
        securityhub_findings,
        securityhub_errors,
        securityhub_service
    ) = scan_client_securityhub(role_arn)

    scan_errors.extend(
        securityhub_errors
    )

    print("Scanning GuardDuty")

    (
        guardduty_findings,
        guardduty_errors,
        guardduty_service
    ) = scan_client_guardduty(role_arn)

    scan_errors.extend(
        guardduty_errors
    )

    print("Scanning AWS Config")

    (
        config_findings,
        config_errors,
        config_service
    ) = scan_client_config(role_arn)

    scan_errors.extend(
        config_errors
    )

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

    for securityhub_finding in securityhub_findings:
        severity = str(
            securityhub_finding.get(
                "severity",
                "UNKNOWN"
            )
        ).upper()

        if severity not in {
            "CRITICAL",
            "HIGH"
        }:
            continue

        priority = severity
        risk_score = (
            95
            if severity == "CRITICAL"
            else 80
        )

        client_findings.append({
            "cve_id": (
                "Security Hub - "
                f"{securityhub_finding.get('title')} - "
                f"{securityhub_finding.get('region')} - "
                f"{securityhub_finding.get('resource')}"
            ),
            "priority": priority,
            "risk_score": risk_score
        })

    for guardduty_finding in guardduty_findings:
        try:
            severity = float(
                guardduty_finding.get(
                    "severity",
                    0
                )
            )
        except (TypeError, ValueError):
            severity = 0

        if severity < 7:
            continue

        client_findings.append({
            "cve_id": (
                "GuardDuty - "
                f"{guardduty_finding.get('title')} - "
                f"{guardduty_finding.get('region')} - "
                f"{guardduty_finding.get('finding_id')}"
            ),
            "priority": "HIGH",
            "risk_score": 90
        })

    for config_finding in config_findings:
        rule_name = config_finding.get(
            "rule_name",
            "Unknown Rule"
        )

        region = config_finding.get(
            "region",
            "Unknown Region"
        )

        resource_count = config_finding.get(
            "noncompliant_resource_count"
        )

        if isinstance(resource_count, int):
            resource_text = (
                f"{resource_count} Noncompliant "
                f"Resource"
                f"{'s' if resource_count != 1 else ''}"
            )
        else:
            resource_text = (
                "Noncompliant Resources Detected"
            )

        client_findings.append({
            "cve_id": (
                f"AWS Config - {rule_name} - "
                f"{region} - {resource_text}"
            ),
            "priority": "HIGH",
            "risk_score": 80
        })

    remediation_plan = generate_remediation_plan(
        client_findings
    )

    if remediation_plan:
        bound_client_name = (
            client_name
            or f"AWS Account {account_id}"
        )

        save_remediation_items(
            remediation_plan,
            aws_account_id=account_id,
            client_name=bound_client_name,
        )

        create_actions_from_remediation_plan(
            remediation_plan,
            aws_account_id=account_id,
            client_name=bound_client_name,
            role_arn=role_arn,
        )

    securityhub_critical = sum(
        str(item.get("severity", "")).upper()
        == "CRITICAL"
        for item in securityhub_findings
    )

    securityhub_high = sum(
        str(item.get("severity", "")).upper()
        == "HIGH"
        for item in securityhub_findings
    )

    guardduty_high = 0

    for item in guardduty_findings:
        try:
            finding_severity = float(
                item.get("severity", 0)
            )
        except (TypeError, ValueError):
            finding_severity = 0

        if finding_severity >= 7:
            guardduty_high += 1

    save_client_scan_summary(
        account_id,
        {
            "scan_time": scan_time,
            "ec2_count": len(ec2_instances),
            "iam_count": len(iam_users),
            "s3_count": len(s3_buckets),
            "securityhub_count": len(
                securityhub_findings
            ),
            "securityhub_critical": (
                securityhub_critical
            ),
            "securityhub_high": securityhub_high,
            "securityhub_status": (
                securityhub_service.get(
                    "status",
                    "Unknown"
                )
            ),
            "guardduty_count": len(
                guardduty_findings
            ),
            "guardduty_critical": 0,
            "guardduty_high": guardduty_high,
            "guardduty_status": (
                guardduty_service.get(
                    "status",
                    "Unknown"
                )
            ),
            "config_rule_count": (
                config_service.get(
                    "rule_count",
                    0
                )
            ),
            "config_noncompliant_rule_count": (
                config_service.get(
                    "noncompliant_rule_count",
                    0
                )
            ),
            "config_noncompliant_resource_count": (
                config_service.get(
                    "noncompliant_resource_count",
                    0
                )
            ),
            "config_critical": 0,
            "config_high": (
                config_service.get(
                    "noncompliant_rule_count",
                    0
                )
            ),
            "config_status": (
                config_service.get(
                    "status",
                    "Unknown"
                )
            ),
            "scan_errors": scan_errors
        }
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
        "securityhub_findings": securityhub_findings,
        "securityhub_count": len(securityhub_findings),
        "securityhub_service": securityhub_service,
        "guardduty_findings": guardduty_findings,
        "guardduty_count": len(guardduty_findings),
        "guardduty_service": guardduty_service,
        "config_findings": config_findings,
        "config_rule_count": config_service.get(
            "rule_count",
            0
        ),
        "config_noncompliant_rule_count": (
            config_service.get(
                "noncompliant_rule_count",
                0
            )
        ),
        "config_noncompliant_resource_count": (
            config_service.get(
                "noncompliant_resource_count",
                0
            )
        ),
        "config_service": config_service,
        "remediation_findings": client_findings,
        "remediation_plan": remediation_plan,
        "remediation_count": len(remediation_plan),
        "scan_errors": scan_errors,
    }
