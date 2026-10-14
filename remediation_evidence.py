"""Pure remediation evidence payload and authentication helpers.

No configuration, SQLite initialization, cloud calls, or audit writes occur here.
"""

import hashlib
import hmac
import json
import re

EVIDENCE_AUTHENTICATION_TYPE = "HMAC-SHA256"


def evidence_key_id(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def calculate_evidence_hash(evidence, key):
    canonical = json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def build_execution_evidence(
    action_id,
    finding,
    action_type,
    approval_status,
    execution_status,
    execution_mode,
    aws_account_id,
    client_name,
    role_arn,
    adapter,
    resource_id,
    request_id,
    verification_request_id,
    verification_status,
    result_message,
    executed_at,
):
    return {
        "action_id": action_id,
        "finding": finding,
        "action_type": action_type,
        "approval_status": approval_status,
        "execution_status": execution_status,
        "execution_mode": execution_mode,
        "aws_account_id": aws_account_id,
        "client_name": client_name,
        "role_arn": role_arn,
        "adapter": adapter,
        "resource_id": resource_id,
        "request_id": request_id,
        "verification_request_id": verification_request_id,
        "verification_status": verification_status,
        "result_message": result_message,
        "executed_at": executed_at,
    }


def verify_stored_evidence(evidence, stored_hash, authentication_type, stored_key_id, keys=()):
    """Return a status only; never return hashes, key identifiers, or payloads."""
    if not stored_hash:
        if authentication_type or stored_key_id:
            return "MALFORMED"
        if evidence.get("execution_mode") == "Live" and evidence.get("execution_status") in {"Completed", "Failed"}:
            return "MISSING"
        if evidence.get("execution_mode") == "Simulation":
            return "NOT_REQUIRED_FOR_SIMULATION"
        return "NOT_RECORDED"
    if authentication_type != EVIDENCE_AUTHENTICATION_TYPE:
        return "UNSUPPORTED"
    if (not isinstance(stored_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", stored_hash)
            or not isinstance(stored_key_id, str) or not re.fullmatch(r"[0-9a-f]{16}", stored_key_id)):
        return "MALFORMED"
    if not keys:
        return "KEY_UNAVAILABLE"
    matching = [key for key in keys if evidence_key_id(key) == stored_key_id]
    if not matching:
        return "KEY_MISMATCH"
    try:
        if any(hmac.compare_digest(stored_hash, calculate_evidence_hash(evidence, key)) for key in matching):
            return "VERIFIED"
        return "TAMPERED"
    except (TypeError, ValueError, OverflowError):
        return "MALFORMED"
