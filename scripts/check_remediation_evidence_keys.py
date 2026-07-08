"""Validate remediation evidence keys before and after HMAC rotation.

Usage:
    export DGS_REMEDIATION_EVIDENCE_HMAC_KEY="current-key"
    export DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS="old-key-one,old-key-two"
    python -m scripts.check_remediation_evidence_keys
"""

from __future__ import annotations

from collections import Counter

import remediation_execution


def validate_key_rotation() -> dict:
    verification_keys = (
        remediation_execution._get_evidence_verification_keys()
    )
    key_ids = tuple(
        remediation_execution._get_evidence_key_id(key)
        for key in verification_keys
    )

    actions = remediation_execution.get_execution_actions()
    signed_action_ids = [
        action[0]
        for action in actions
        if len(action) > 19 and action[19]
    ]

    results = [
        remediation_execution.verify_execution_evidence(
            action_id,
            actor="Key Rotation Validator",
        )
        for action_id in signed_action_ids
    ]
    status_counts = Counter(
        result["status"]
        for result in results
    )

    return {
        "current_key_id": key_ids[0],
        "previous_key_ids": key_ids[1:],
        "signed_record_count": len(signed_action_ids),
        "status_counts": dict(status_counts),
        "successful": all(
            result["status"] == "VERIFIED"
            for result in results
        ),
    }


def main() -> int:
    try:
        report = validate_key_rotation()

    except RuntimeError as error:
        print(f"Configuration error: {error}")
        return 2

    print(f"Current evidence key ID: {report['current_key_id']}")
    print(
        "Previous evidence key IDs: "
        + (
            ", ".join(report["previous_key_ids"])
            if report["previous_key_ids"]
            else "None"
        )
    )
    print(
        "Signed remediation evidence records: "
        f"{report['signed_record_count']}"
    )

    if report["status_counts"]:
        for status, count in sorted(
            report["status_counts"].items()
        ):
            print(f"{status}: {count}")
    else:
        print("No signed remediation evidence records were found.")

    if report["successful"]:
        print("Key rotation validation successful.")
        return 0

    print("Key rotation validation failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
