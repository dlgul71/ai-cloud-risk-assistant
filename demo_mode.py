import os


DEMO_MODE = (
    os.getenv("DGS_PUBLIC_DEMO_MODE", "false")
    .strip()
    .lower()
    == "true"
)


DEMO_ACCOUNT_ID = "123456789012"
DEMO_CLIENT_NAME = "Demo Healthcare Client"


def demo_mode_enabled():
    return DEMO_MODE


def sanitize_text(value):
    if not DEMO_MODE:
        return value

    if value is None:
        return value

    text = str(value)

    replacements = {
        "975049950898": DEMO_ACCOUNT_ID,
        "DGS Internal AWS": DEMO_CLIENT_NAME,
        "ai-cloud-risk-assistant-user": "demo-cloud-admin",
        "terraform-en-1": "demo-terraform-user",
        "dgs-sentinel-ai-test-bucket-975049950898": (
            "demo-security-assessment-bucket"
        ),
        "phase8-controlled-test-bucket": (
            "demo-controlled-test-bucket"
        )
    }

    for original, replacement in replacements.items():
        text = text.replace(
            original,
            replacement
        )

    return text


def sanitize_value(value):
    if not DEMO_MODE:
        return value

    if isinstance(value, dict):
        return {
            key: sanitize_value(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            sanitize_value(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            sanitize_value(item)
            for item in value
        )

    if isinstance(value, str):
        return sanitize_text(value)

    return value


def sanitize_record(record):
    return sanitize_value(record)


def sanitize_records(records):
    return sanitize_value(records)
