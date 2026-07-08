import sqlite3

import pytest

import remediation_audit
import remediation_execution


S3_ACTION = "Generate S3 Exposure Remediation Task"
CONFIRMATION = "AUTHORIZE LIVE AWS REMEDIATION"


@pytest.fixture
def execution_database(tmp_path, monkeypatch):
    database_path = tmp_path / "remediation_actions.db"

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        "phase-21-test-signing-key-0123456789abcdef",
    )

    monkeypatch.setattr(
        remediation_execution,
        "DB_NAME",
        str(database_path),
    )
    monkeypatch.setattr(
        remediation_audit,
        "DB_NAME",
        str(database_path),
    )

    remediation_execution.init_execution_db()

    return database_path


def insert_action(
    database_path,
    approval_status="Approved",
    execution_status="Ready",
):
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO remediation_actions (
            created_at,
            finding,
            action_type,
            priority,
            approval_status,
            execution_status,
            execution_mode,
            notes,
            aws_account_id,
            client_name,
            role_arn
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "2026-06-30T00:00:00+00:00",
            "S3 Risk - example-security-bucket",
            S3_ACTION,
            "HIGH",
            approval_status,
            execution_status,
            "Simulation",
            "Phase 17 integration test",
            "123456789012",
            "Example Client",
            (
                "arn:aws:iam::123456789012:"
                "role/DGSSentinelRemediation"
            ),
        ),
    )

    action_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return action_id


def read_action(database_path, action_id):
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT approval_status, execution_status, execution_mode
        FROM remediation_actions
        WHERE id = ?
        """,
        (action_id,),
    )

    action = cursor.fetchone()

    connection.close()

    return action


def read_execution_evidence(database_path, action_id):
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            adapter,
            resource_id,
            request_id,
            verification_request_id,
            verification_status,
            result_message,
            executed_at
        FROM remediation_actions
        WHERE id = ?
        """,
        (action_id,),
    )

    evidence = cursor.fetchone()
    connection.close()

    return evidence


def read_audit_events(database_path, action_id):
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT event_type, event_detail, actor
        FROM remediation_audit
        WHERE action_id = ?
        ORDER BY id
        """,
        (action_id,),
    )

    events = cursor.fetchall()

    connection.close()

    return events


def test_execute_live_action_completes_and_audits(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    result = remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
        actor="Security Administrator",
    )

    assert result["status"] == "Completed"
    assert result["mode"] == "Live"
    assert result["adapter"] == "S3_BLOCK_PUBLIC_ACCESS"

    assert read_action(
        execution_database,
        action_id,
    ) == (
        "Approved",
        "Completed",
        "Live",
    )

    events = read_audit_events(
        execution_database,
        action_id,
    )

    assert events[-1][0] == "LIVE_REMEDIATION_COMPLETED"
    assert events[-1][2] == "Security Administrator"
    assert "request-123" in events[-1][1]

    evidence = read_execution_evidence(
        execution_database,
        action_id,
    )

    assert evidence[:6] == (
        "S3_BLOCK_PUBLIC_ACCESS",
        "example-security-bucket",
        "request-123",
        "verify-123",
        "VERIFIED",
        "S3 Block Public Access was enabled and verified.",
    )
    assert evidence[6] is not None


def test_execute_live_action_requires_approval(
    execution_database,
):
    action_id = insert_action(
        execution_database,
        approval_status="Pending Approval",
        execution_status="Not Started",
    )

    with pytest.raises(
        ValueError,
        match="approved",
    ):
        remediation_execution.execute_live_action(
            action_id=action_id,
            expected_account_id="123456789012",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )

    assert read_action(
        execution_database,
        action_id,
    ) == (
        "Pending Approval",
        "Not Started",
        "Simulation",
    )


def test_execute_live_action_records_failed_result(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "FAILED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "message": "AWS denied the remediation request.",
        },
    )

    with pytest.raises(
        ValueError,
        match="AWS denied",
    ):
        remediation_execution.execute_live_action(
            action_id=action_id,
            expected_account_id="123456789012",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )

    assert read_action(
        execution_database,
        action_id,
    ) == (
        "Approved",
        "Failed",
        "Live",
    )

    events = read_audit_events(
        execution_database,
        action_id,
    )

    assert events[-1][0] == "LIVE_REMEDIATION_FAILED"


def test_execute_live_action_rejects_completed_action(
    execution_database,
):
    action_id = insert_action(
        execution_database,
        execution_status="Completed",
    )

    with pytest.raises(
        ValueError,
        match="already completed",
    ):
        remediation_execution.execute_live_action(
            action_id=action_id,
            expected_account_id="123456789012",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )


def test_create_execution_action_stores_account_binding(
    execution_database,
):
    result = remediation_execution.create_execution_action(
        finding="S3 Risk - bound-security-bucket",
        action_type=S3_ACTION,
        priority="HIGH",
        notes="Bound action test",
        aws_account_id="123456789012",
        client_name="Example Client",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/DGSSentinelRemediation"
        ),
    )

    connection = sqlite3.connect(execution_database)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            aws_account_id,
            client_name,
            role_arn
        FROM remediation_actions
        WHERE id = ?
        """,
        (result["action_id"],),
    )

    binding = cursor.fetchone()

    connection.close()

    assert binding == (
        "123456789012",
        "Example Client",
        (
            "arn:aws:iam::123456789012:"
            "role/DGSSentinelRemediation"
        ),
    )


def test_execute_live_action_rejects_account_mismatch(
    execution_database,
    monkeypatch,
):
    result = remediation_execution.create_execution_action(
        finding="S3 Risk - bound-security-bucket",
        action_type=S3_ACTION,
        priority="HIGH",
        notes="Bound action test",
        aws_account_id="123456789012",
        client_name="Example Client",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/DGSSentinelRemediation"
        ),
    )

    remediation_execution.update_execution_action(
        action_id=result["action_id"],
        approval_status="Approved",
        execution_status="Ready",
    )

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: pytest.fail(
            "AWS adapter must not run for an account mismatch."
        ),
    )

    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        remediation_execution.execute_live_action(
            action_id=result["action_id"],
            expected_account_id="999999999999",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )


def test_execute_live_action_rejects_unverified_execution(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "FAILED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": (
                "The AWS write completed, but the final state "
                "could not be verified."
            ),
        },
    )

    with pytest.raises(
        ValueError,
        match="could not be verified",
    ):
        remediation_execution.execute_live_action(
            action_id=action_id,
            expected_account_id="123456789012",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )

    assert read_action(
        execution_database,
        action_id,
    ) == (
        "Approved",
        "Failed",
        "Live",
    )

    events = read_audit_events(
        execution_database,
        action_id,
    )

    assert events[-1][0] == "LIVE_REMEDIATION_VERIFICATION_FAILED"
    assert "verify-123" in events[-1][1]

    evidence = read_execution_evidence(
        execution_database,
        action_id,
    )

    assert evidence[:6] == (
        "S3_BLOCK_PUBLIC_ACCESS",
        "example-security-bucket",
        "request-123",
        "verify-123",
        "FAILED",
        (
            "The AWS write completed, but the final state "
            "could not be verified."
        ),
    )
    assert evidence[6] is not None


def test_get_execution_actions_returns_structured_evidence(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    actions = remediation_execution.get_execution_actions()
    action = next(row for row in actions if row[0] == action_id)

    assert action[12:18] == (
        "S3_BLOCK_PUBLIC_ACCESS",
        "example-security-bucket",
        "request-123",
        "verify-123",
        "VERIFIED",
        "S3 Block Public Access was enabled and verified.",
    )
    assert action[18] is not None
    assert len(action[19]) == 64


def test_live_action_persists_tamper_evident_hash(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "VERIFIED"
    assert len(integrity["stored_hash"]) == 64
    assert integrity["stored_hash"] == integrity["calculated_hash"]


def test_verify_execution_evidence_detects_tampering(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    connection = sqlite3.connect(execution_database)
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE remediation_actions
        SET result_message = ?
        WHERE id = ?
        """,
        (
            "Tampered remediation evidence.",
            action_id,
        ),
    )
    connection.commit()
    connection.close()

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "TAMPERED"
    assert integrity["stored_hash"] != integrity["calculated_hash"]


def test_live_action_uses_hmac_authenticated_evidence(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    connection = sqlite3.connect(execution_database)
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT
            evidence_hash,
            evidence_authentication_type,
            evidence_key_id
        FROM remediation_actions
        WHERE id = ?
        """,
        (action_id,),
    )
    stored_hash, authentication_type, key_id = cursor.fetchone()
    connection.close()

    assert len(stored_hash) == 64
    assert authentication_type == "HMAC-SHA256"
    assert len(key_id) == 16

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "VERIFIED"
    assert integrity["authentication_type"] == "HMAC-SHA256"
    assert integrity["key_id"] == key_id


def test_verify_execution_evidence_detects_wrong_hmac_key(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "verification_request_id": "verify-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        "phase21-different-test-key",
    )

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "KEY_MISMATCH"


def test_live_action_requires_hmac_key_before_aws_execution(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.delenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        raising=False,
    )

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: pytest.fail(
            "AWS execution must not start without an evidence HMAC key."
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
    ):
        remediation_execution.execute_live_action(
            action_id=action_id,
            expected_account_id="123456789012",
            s3_client=object(),
            confirmation_phrase=CONFIRMATION,
        )


def test_rotated_previous_hmac_key_verifies_existing_evidence(
    execution_database,
    monkeypatch,
):
    original_key = "phase22-original-signing-key"
    rotated_key = "phase22-rotated-signing-key"

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        original_key,
    )

    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-rotation-123",
            "verification_request_id": "verify-rotation-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        rotated_key,
    )
    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS",
        original_key,
    )

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "VERIFIED"
    assert integrity["key_id"] == (
        remediation_execution._get_evidence_key_id(original_key)
    )


def test_rotated_key_without_previous_key_returns_key_mismatch(
    execution_database,
    monkeypatch,
):
    original_key = "phase22-original-signing-key"
    rotated_key = "phase22-rotated-signing-key"

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        original_key,
    )

    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-rotation-456",
            "verification_request_id": "verify-rotation-456",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        rotated_key,
    )
    monkeypatch.delenv(
        "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS",
        raising=False,
    )

    integrity = remediation_execution.verify_execution_evidence(
        action_id
    )

    assert integrity["status"] == "KEY_MISMATCH"


def test_verify_execution_evidence_audits_verified_result(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-audit-123",
            "verification_request_id": "verify-audit-123",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    integrity = remediation_execution.verify_execution_evidence(
        action_id,
        actor="Evidence Auditor",
    )

    events = read_audit_events(
        execution_database,
        action_id,
    )

    assert integrity["status"] == "VERIFIED"
    assert (
        events[-1][0]
        == "REMEDIATION_EVIDENCE_VERIFICATION_VERIFIED"
    )
    assert "Status=VERIFIED" in events[-1][1]
    assert "AuthenticationType=HMAC-SHA256" in events[-1][1]
    assert events[-1][2] == "Evidence Auditor"


def test_verify_execution_evidence_audits_tampered_result(
    execution_database,
    monkeypatch,
):
    action_id = insert_action(execution_database)

    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "verification_status": "VERIFIED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-audit-456",
            "verification_request_id": "verify-audit-456",
            "message": "S3 Block Public Access was enabled and verified.",
        },
    )

    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase=CONFIRMATION,
    )

    connection = sqlite3.connect(execution_database)
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE remediation_actions
        SET result_message = ?
        WHERE id = ?
        """,
        ("Tampered evidence message", action_id),
    )
    connection.commit()
    connection.close()

    integrity = remediation_execution.verify_execution_evidence(
        action_id,
        actor="Evidence Auditor",
    )

    events = read_audit_events(
        execution_database,
        action_id,
    )

    assert integrity["status"] == "TAMPERED"
    assert (
        events[-1][0]
        == "REMEDIATION_EVIDENCE_VERIFICATION_TAMPERED"
    )
    assert "Status=TAMPERED" in events[-1][1]
    assert events[-1][2] == "Evidence Auditor"
