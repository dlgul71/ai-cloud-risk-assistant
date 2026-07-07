import pytest

from remediation_aws_adapters import (
    S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION,
    build_s3_public_access_block_request,
    execute_s3_public_access_block,
)


class FakeS3Client:
    def __init__(self):
        self.request = None
        self.get_request = None

    def put_public_access_block(self, **kwargs):
        self.request = kwargs

        return {
            "ResponseMetadata": {
                "RequestId": "test-request-id",
                "HTTPStatusCode": 200,
            }
        }

    def get_public_access_block(self, **kwargs):
        self.get_request = kwargs

        return {
            "PublicAccessBlockConfiguration": dict(
                S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
            ),
            "ResponseMetadata": {
                "RequestId": "verification-request-id",
                "HTTPStatusCode": 200,
            },
        }


def test_build_s3_request_enables_all_public_access_controls():
    request = build_s3_public_access_block_request(
        bucket_name="example-security-bucket",
        expected_bucket_owner="123456789012",
    )

    assert request == {
        "Bucket": "example-security-bucket",
        "ExpectedBucketOwner": "123456789012",
        "PublicAccessBlockConfiguration": (
            S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
        ),
    }


@pytest.mark.parametrize(
    "bucket_name",
    [
        "",
        "   ",
        "invalid bucket name",
    ],
)
def test_build_s3_request_rejects_invalid_bucket_name(
    bucket_name,
):
    with pytest.raises(ValueError):
        build_s3_public_access_block_request(
            bucket_name=bucket_name,
            expected_bucket_owner="123456789012",
        )


@pytest.mark.parametrize(
    "account_id",
    [
        "",
        "1234",
        "abcdefghijkl",
        "1234567890123",
    ],
)
def test_build_s3_request_rejects_invalid_account_id(
    account_id,
):
    with pytest.raises(ValueError):
        build_s3_public_access_block_request(
            bucket_name="example-security-bucket",
            expected_bucket_owner=account_id,
        )


def test_execute_s3_public_access_block_uses_injected_client():
    client = FakeS3Client()

    result = execute_s3_public_access_block(
        bucket_name="example-security-bucket",
        expected_bucket_owner="123456789012",
        s3_client=client,
    )

    assert client.request == {
        "Bucket": "example-security-bucket",
        "ExpectedBucketOwner": "123456789012",
        "PublicAccessBlockConfiguration": (
            S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
        ),
    }

    assert result["status"] == "EXECUTED"
    assert result["adapter"] == "S3_BLOCK_PUBLIC_ACCESS"
    assert result["resource_id"] == "example-security-bucket"
    assert result["request_id"] == "test-request-id"
    assert result["http_status_code"] == 200


def test_execute_s3_public_access_block_requires_client():
    with pytest.raises(
        ValueError,
        match="authenticated S3 client",
    ):
        execute_s3_public_access_block(
            bucket_name="example-security-bucket",
            expected_bucket_owner="123456789012",
            s3_client=None,
        )


class VerifyingFakeS3Client(FakeS3Client):
    def __init__(self, verified_configuration=None):
        super().__init__()
        self.get_request = None
        self.verified_configuration = (
            verified_configuration
            or dict(S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION)
        )

    def get_public_access_block(self, **kwargs):
        self.get_request = kwargs

        return {
            "PublicAccessBlockConfiguration": (
                self.verified_configuration
            ),
            "ResponseMetadata": {
                "RequestId": "verification-request-id",
                "HTTPStatusCode": 200,
            },
        }


def test_execute_s3_public_access_block_verifies_final_state():
    client = VerifyingFakeS3Client()

    result = execute_s3_public_access_block(
        bucket_name="example-security-bucket",
        expected_bucket_owner="123456789012",
        s3_client=client,
    )

    assert client.get_request == {
        "Bucket": "example-security-bucket",
        "ExpectedBucketOwner": "123456789012",
    }
    assert result["status"] == "EXECUTED"
    assert result["verification_status"] == "VERIFIED"
    assert result["verified_configuration"] == (
        S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
    )
    assert result["verification_request_id"] == (
        "verification-request-id"
    )


def test_execute_s3_public_access_block_fails_unverified_state():
    client = VerifyingFakeS3Client(
        verified_configuration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        }
    )

    result = execute_s3_public_access_block(
        bucket_name="example-security-bucket",
        expected_bucket_owner="123456789012",
        s3_client=client,
    )

    assert result["status"] == "FAILED"
    assert result["verification_status"] == "FAILED"
    assert "could not be verified" in result["message"]
