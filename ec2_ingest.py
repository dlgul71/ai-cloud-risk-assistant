import boto3


def get_ec2_assets(region="us-east-1"):

    assets = []

    try:
        ec2 = boto3.client("ec2", region_name=region)

        response = ec2.describe_instances()

        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):

                name = ""

                for tag in instance.get("Tags", []):
                    if tag.get("Key") == "Name":
                        name = tag.get("Value", "")

                assets.append({
                    "Instance ID": instance.get("InstanceId"),
                    "Name": name,
                    "State": instance.get("State", {}).get("Name"),
                    "Instance Type": instance.get("InstanceType"),
                    "Private IP": instance.get("PrivateIpAddress", ""),
                    "Public IP": instance.get("PublicIpAddress", ""),
                    "Internet Facing": bool(instance.get("PublicIpAddress")),
                })

        return assets

    except Exception as e:
        print(f"EC2 ingest error: {e}")
        return []
