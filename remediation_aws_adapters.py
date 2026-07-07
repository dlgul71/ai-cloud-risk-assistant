"""Guarded AWS remediation adapters for DGS Sentinel AI."""

from __future__ import annotations

from typing import Any


S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def build_s3_public_access_block_request(
    bucket_name: str,
    expected_bucket_owner: str,
) -> dict[str, Any]:
    """Build a validated S3 Block Public Access request."""

    normalized_bucket = str(bucket_name or "").strip()
    normalized_owner = str(expected_bucket_owner or "").strip()

    if not normalized_bucket:
        raise ValueError("An S3 bucket name is required.")

    if any(character.isspace() for character in normalized_bucket):
        raise ValueError(
            "The S3 bucket name cannot contain whitespace."
        )

    if (
        len(normalized_owner) != 12
        or not normalized_owner.isdigit()
    ):
        raise ValueError(
            "Expected bucket owner must be a 12-digit AWS account ID."
        )

    return {
        "Bucket": normalized_bucket,
        "ExpectedBucketOwner": normalized_owner,
        "PublicAccessBlockConfiguration": dict(
            S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
        ),
    }


def execute_s3_public_access_block(
    bucket_name: str,
    expected_bucket_owner: str,
    s3_client: Any,
) -> dict[str, Any]:
    """Enable all four S3 bucket-level public-access protections."""

    if s3_client is None:
        raise ValueError(
            "An authenticated S3 client is required for live execution."
        )

    request = build_s3_public_access_block_request(
        bucket_name=bucket_name,
        expected_bucket_owner=expected_bucket_owner,
    )

    response = s3_client.put_public_access_block(
        **request
    )

    response_metadata = (
        response.get("ResponseMetadata", {})
        if isinstance(response, dict)
        else {}
    )

    verification_response = s3_client.get_public_access_block(
        Bucket=request["Bucket"],
        ExpectedBucketOwner=request["ExpectedBucketOwner"],
    )

    verified_configuration = (
        verification_response.get(
            "PublicAccessBlockConfiguration",
            {},
        )
        if isinstance(verification_response, dict)
        else {}
    )

    verification_metadata = (
        verification_response.get("ResponseMetadata", {})
        if isinstance(verification_response, dict)
        else {}
    )

    is_verified = all(
        verified_configuration.get(control_name) is True
        for control_name in S3_PUBLIC_ACCESS_BLOCK_CONFIGURATION
    )

    if not is_verified:
        return {
            "status": "FAILED",
            "verification_status": "FAILED",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_type": "S3_BUCKET",
            "resource_id": request["Bucket"],
            "expected_bucket_owner": request[
                "ExpectedBucketOwner"
            ],
            "configuration": request[
                "PublicAccessBlockConfiguration"
            ],
            "verified_configuration": verified_configuration,
            "request_id": response_metadata.get("RequestId"),
            "verification_request_id": verification_metadata.get(
                "RequestId"
            ),
            "http_status_code": response_metadata.get(
                "HTTPStatusCode"
            ),
            "verification_http_status_code": (
                verification_metadata.get("HTTPStatusCode")
            ),
            "message": (
                "S3 Block Public Access was requested but the final "
                "bucket configuration could not be verified."
            ),
        }

    return {
        "status": "EXECUTED",
        "verification_status": "VERIFIED",
        "adapter": "S3_BLOCK_PUBLIC_ACCESS",
        "resource_type": "S3_BUCKET",
        "resource_id": request["Bucket"],
        "expected_bucket_owner": request[
            "ExpectedBucketOwner"
        ],
        "configuration": request[
            "PublicAccessBlockConfiguration"
        ],
        "verified_configuration": verified_configuration,
        "request_id": response_metadata.get("RequestId"),
        "verification_request_id": verification_metadata.get(
            "RequestId"
        ),
        "http_status_code": response_metadata.get(
            "HTTPStatusCode"
        ),
        "verification_http_status_code": (
            verification_metadata.get("HTTPStatusCode")
        ),
        "message": (
            "S3 Block Public Access was enabled and verified."
        ),
    }
