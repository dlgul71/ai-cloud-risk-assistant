import boto3


def get_s3_exposure_findings():

    findings = []

    try:
        s3 = boto3.client("s3")

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:

            bucket_name = bucket.get("Name")

            public_access_blocked = False
            encryption_enabled = False

            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})

                public_access_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])

            except Exception:
                public_access_blocked = False

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                encryption_enabled = True

            except Exception:
                encryption_enabled = False

            risk = "LOW"

            if not public_access_blocked:
                risk = "HIGH"

            if not encryption_enabled:
                risk = "MODERATE" if risk == "LOW" else "HIGH"

            findings.append({
                "Bucket": bucket_name,
                "Public Access Blocked": public_access_blocked,
                "Encryption Enabled": encryption_enabled,
                "Risk": risk
            })

        return findings

    except Exception as e:
        print(f"S3 ingest error: {e}")
        return []
