import sqlite3

import pytest

import remediation_audit
import remediation_execution


S3_ACTION = "Generate S3 Exposure Remediation Task"
CONFIRMATION = "AUTHORIZE LIVE AWS REMEDIATION"


@pytest.fixture
def execution_database(tmp_path, monkeypatch):
    database_path = tmp_path / "remediation_actions.db"

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
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "example-security-bucket",
            "request_id": "request-123",
            "message": "S3 Block Public Access was enabled.",
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
