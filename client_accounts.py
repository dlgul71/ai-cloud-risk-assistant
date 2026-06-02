import boto3


def assume_client_role(role_arn, session_name="DGS-Sentinel-Client-Scan"):
    """
    Assume a client AWS read-only role and return temporary credentials.
    """

    try:
        sts = boto3.client("sts")

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )

        return response["Credentials"]

    except Exception as e:
        print(f"AssumeRole error: {e}")
        return None


def client_boto3_client(service_name, role_arn, region_name="us-east-1"):
    """
    Create a boto3 client for a client AWS account using AssumeRole.
    """

    credentials = assume_client_role(role_arn)

    if not credentials:
        return None

    return boto3.client(
        service_name,
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=region_name
    )
