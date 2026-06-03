from datetime import datetime
from client_accounts import client_boto3_client


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
        "scan_time": str(datetime.utcnow())
    }


def scan_client_ec2(role_arn, region_name="us-east-1"):
    ec2 = client_boto3_client("ec2", role_arn, region_name)

    if not ec2:
        return []

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
                "region": region_name
            })

    return instances


def run_client_scan(role_arn, region_name="us-east-1"):
    print("=" * 60)
    print("DGS SENTINEL AI PHASE 3 ASSUMEROLE SCAN")
    print("=" * 60)

    identity = test_client_identity(role_arn)
    print(identity)

    if identity["status"] != "SUCCESS":
        return {
            "identity": identity,
            "ec2_instances": []
        }

    ec2_instances = scan_client_ec2(role_arn, region_name)

    return {
        "identity": identity,
        "ec2_instances": ec2_instances
    }

ROLE_ARN = "arn:aws:iam::975049950898:role/DGS-Sentinel-ReadOnly"
if __name__ == "__main__":

    ROLE_ARN = "arn:aws:iam::975049950898:role/DGS-Sentinel-ReadOnly"
    results = run_client_scan(ROLE_ARN)

    print("\nSCAN RESULTS")
    print(results)
