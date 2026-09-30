from contextlib import closing
import sqlite3

import pytest

import remediation_audit
import remediation_execution


@pytest.fixture(autouse=True)
def default_storage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DGS_DATA_DIR", raising=False)
    monkeypatch.setattr(remediation_execution, "DB_NAME", None)
    monkeypatch.setattr(remediation_audit, "DB_NAME", None)


def create_action():
    return remediation_execution.create_execution_action(
        finding="S3 Risk - storage-test-bucket",
        action_type="Generate S3 Exposure Remediation Task",
        aws_account_id="123456789012",
        client_name="Storage Test Client",
        role_arn="arn:aws:iam::123456789012:role/StorageTest",
    )["action_id"]


def read_rows(path, table):
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute(
            {
                "remediation_actions": "SELECT * FROM remediation_actions ORDER BY id",
                "remediation_audit": "SELECT * FROM remediation_audit ORDER BY id",
            }[table]
        ).fetchall()


def test_execution_and_audit_share_configured_storage(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))

    action_id = create_action()
    remediation_execution.update_execution_action(
        action_id, approval_status="Approved", execution_status="Ready"
    )

    assert remediation_execution.get_execution_actions()[0][0] == action_id
    events = remediation_audit.get_remediation_audit()
    assert [event[3] for event in events] == ["ACTION_UPDATED", "ACTION_CREATED"]
    assert all(event[2] == action_id for event in events)
    assert (data_dir / "remediation_actions.db").is_file()
    assert not (tmp_path / "remediation_actions.db").exists()


@pytest.mark.parametrize("setting", [None, "   "])
def test_unconfigured_storage_uses_working_directory(tmp_path, monkeypatch, setting):
    if setting is not None:
        monkeypatch.setenv("DGS_DATA_DIR", setting)

    action_id = create_action()

    assert (tmp_path / "remediation_actions.db").is_file()
    assert remediation_audit.get_remediation_audit()[0][2] == action_id


def test_explicit_overrides_take_precedence(tmp_path, monkeypatch):
    override = tmp_path / "override.db"
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path / "missing"))
    monkeypatch.setattr(remediation_execution, "DB_NAME", str(override))
    monkeypatch.setattr(remediation_audit, "DB_NAME", str(override))

    action_id = create_action()

    assert override.is_file()
    assert remediation_execution.get_execution_actions()[0][0] == action_id
    assert remediation_audit.get_remediation_audit()[0][2] == action_id
    assert not (tmp_path / "remediation_actions.db").exists()


@pytest.mark.parametrize(
    "initialize",
    [remediation_execution.init_execution_db, remediation_audit.init_audit_table],
)
def test_missing_data_directory_fails_without_fallback(tmp_path, monkeypatch, initialize):
    monkeypatch.setenv("DGS_DATA_DIR", str(tmp_path / "missing"))

    with pytest.raises(sqlite3.OperationalError):
        initialize()

    assert not (tmp_path / "remediation_actions.db").exists()


def test_setting_is_resolved_at_call_time_without_automatic_relocation(tmp_path, monkeypatch):
    action_id = create_action()
    legacy = tmp_path / "remediation_actions.db"
    original_actions = read_rows(legacy, "remediation_actions")
    original_events = read_rows(legacy, "remediation_audit")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))

    assert remediation_execution.get_execution_actions() == []
    assert remediation_audit.get_remediation_audit() == []
    assert read_rows(legacy, "remediation_actions") == original_actions
    assert read_rows(legacy, "remediation_audit") == original_events
    assert original_actions[0][0] == action_id


def test_sqlite_relocation_preserves_actions_audit_and_signed_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY",
        "storage-test-signing-key-0123456789abcdef",
    )
    monkeypatch.delenv("DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS", raising=False)
    action_id = create_action()
    remediation_execution.update_execution_action(
        action_id, approval_status="Approved", execution_status="Ready"
    )
    # Exercise persisted evidence through the real execution code, with no cloud calls.
    monkeypatch.setattr(
        remediation_execution,
        "execute_controlled_action",
        lambda **kwargs: {
            "status": "EXECUTED",
            "mode": "Live",
            "adapter": "S3_BLOCK_PUBLIC_ACCESS",
            "resource_id": "storage-test-bucket",
            "request_id": "storage-request",
            "verification_request_id": "storage-verification",
            "verification_status": "VERIFIED",
            "message": "Synthetic storage test result.",
        },
    )
    remediation_execution.execute_live_action(
        action_id=action_id,
        expected_account_id="123456789012",
        s3_client=object(),
        confirmation_phrase="AUTHORIZE LIVE AWS REMEDIATION",
        actor="Storage Test Administrator",
    )
    source = tmp_path / "remediation_actions.db"
    actions_before = read_rows(source, "remediation_actions")
    audit_before = read_rows(source, "remediation_audit")
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    destination = data_dir / "remediation_actions.db"
    with closing(sqlite3.connect(source)) as original:
        with closing(sqlite3.connect(destination)) as restored:
            original.backup(restored)
            assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)

    monkeypatch.setenv("DGS_DATA_DIR", str(data_dir))
    for _ in range(2):
        remediation_execution.init_execution_db()
        remediation_audit.init_audit_table()
    assert read_rows(destination, "remediation_actions") == actions_before
    assert read_rows(destination, "remediation_audit") == audit_before
    assert remediation_execution.get_execution_actions()[0][0] == action_id
    result = remediation_execution.verify_execution_evidence(action_id)
    assert result["status"] == "VERIFIED"
    assert result["stored_hash"] == result["calculated_hash"]
    assert read_rows(destination, "remediation_actions") == actions_before
    assert remediation_audit.get_remediation_audit()[0][2:4] == (
        action_id, "REMEDIATION_EVIDENCE_VERIFICATION_VERIFIED"
    )
    assert read_rows(source, "remediation_actions") == actions_before
    assert read_rows(source, "remediation_audit") == audit_before
