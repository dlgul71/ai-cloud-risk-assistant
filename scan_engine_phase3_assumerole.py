from datetime import datetime, UTC
from client_accounts import client_boto3_client
from asset_db import init_asset_db, save_asset
from risk_engine import calculate_asset_risk

REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2"
]


def test_client_identity(role_arn):
    sts = client_boto3_client("sts", role_arn)

    if not sts:
        return {
            "status": "FAILED",
            "message": "Could not assume client role."
        }

    identity = sts.get_caller_identity()

    return {
        "status": "SUCCESS",
        "account": identity.get("Account"),
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
        "scan_time": str(datetime.now(UTC))
    }


def scan_client_ec2(role_arn, region_name="us-east-1"):
    ec2 = client_boto3_client("ec2", role_arn, region_name)

    if not ec2:
        return []

    instances = []

    response = ec2.describe_instances()
    init_asset_db()
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instances.append({
                "instance_id": instance.get("InstanceId"),
                "state": instance.get("State", {}).get("Name"),
                "instance_type": instance.get("InstanceType"),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
                "region": region_name
            })

    return instances


def run_client_scan(role_arn):
    print("=" * 60)
    print("DGS SENTINEL AI PHASE 3 MULTI-REGION ASSUMEROLE SCAN")
    print("=" * 60)

    identity = test_client_identity(role_arn)
    print(identity)

    if identity["status"] != "SUCCESS":
        return {
            "identity": identity,
            "ec2_instances": []
        }

    init_asset_db()

    ec2_instances = []

    for region in REGIONS:
        print(f"Scanning EC2 in region: {region}")

        region_instances = scan_client_ec2(
            role_arn,
            region_name=region
        )

        ec2_instances.extend(region_instances)

        for instance in region_instances:

            asset_record = {
                "asset_id": instance.get("instance_id"),
                "asset_type": "EC2",
                "account_id": identity.get("account"),
                "region": instance.get("region"),
                "hostname": instance.get("instance_id"),
                "ip_address": instance.get("private_ip"),
                "public_ip": instance.get("public_ip"),
                "state": instance.get("state")
            }

            asset_record["risk_score"] = calculate_asset_risk(asset_record)

            save_asset(asset_record)

    return {
        "identity": identity,
        "regions_scanned": REGIONS,
        "ec2_instances": ec2_instances,
        "ec2_count": len(ec2_instances)
    }


if __name__ == "__main__":
    ROLE_ARN = "arn:aws:iam::975049950898:role/DGS-Sentinel-ReadOnly"

    results = run_client_scan(ROLE_ARN)

    print("\nSCAN RESULTS")
    print(results)
