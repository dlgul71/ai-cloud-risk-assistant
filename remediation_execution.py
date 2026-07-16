import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, UTC
from app_config import get_setting
from remediation_audit import log_remediation_event
from remediation_live_actions import execute_controlled_action

DB_NAME = "remediation_actions.db"


EVIDENCE_AUTHENTICATION_TYPE = "HMAC-SHA256"


def _get_evidence_hmac_key():
    key = get_setting(
        "DGS_REMEDIATION_EVIDENCE_HMAC_KEY"
    )

    if key in {None, ""}:
        raise RuntimeError(
            "Required configuration setting is missing: "
            "DGS_REMEDIATION_EVIDENCE_HMAC_KEY"
        )

    return str(key)


def _get_evidence_key_id(key):
    return hashlib.sha256(
        key.encode("utf-8")
    ).hexdigest()[:16]


def _get_previous_evidence_hmac_keys():
    value = get_setting(
        "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS"
    )

    if value in {None, ""}:
        return ()

    return tuple(
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    )


def _get_evidence_verification_keys():
    current_key = _get_evidence_hmac_key()
    keys = (current_key, *_get_previous_evidence_hmac_keys())

    return tuple(dict.fromkeys(keys))


def _calculate_execution_evidence_hash(evidence, key=None):
    signing_key = key or _get_evidence_hmac_key()

    canonical_evidence = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hmac.new(
        signing_key.encode("utf-8"),
        canonical_evidence.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _build_execution_evidence(
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


def init_execution_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS remediation_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        finding TEXT,
        action_type TEXT,
        priority TEXT,
        approval_status TEXT,
        execution_status TEXT,
        execution_mode TEXT,
        notes TEXT,
        aws_account_id TEXT,
        client_name TEXT,
        role_arn TEXT,
        cloud_provider TEXT DEFAULT 'AWS',
        azure_subscription_id TEXT,
        azure_tenant_id TEXT,
        azure_client_id TEXT,
        adapter TEXT,
        resource_id TEXT,
        request_id TEXT,
        verification_request_id TEXT,
        verification_status TEXT,
        result_message TEXT,
        executed_at TEXT,
        evidence_hash TEXT,
        evidence_authentication_type TEXT,
        evidence_key_id TEXT
    )
    """)

    cursor.execute("PRAGMA table_info(remediation_actions)")

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    for column_name in (
        "aws_account_id",
        "client_name",
        "role_arn",
        "cloud_provider",
        "azure_subscription_id",
        "azure_tenant_id",
        "azure_client_id",
        "adapter",
        "resource_id",
        "request_id",
        "verification_request_id",
        "verification_status",
        "result_message",
        "executed_at",
        "evidence_hash",
        "evidence_authentication_type",
        "evidence_key_id",
    ):
        if column_name not in existing_columns:
            cursor.execute(
                f"""
                ALTER TABLE remediation_actions
                ADD COLUMN {column_name} TEXT
                """
            )

    conn.commit()
    conn.close()


def create_execution_action(
    finding,
    action_type,
    priority="STANDARD",
    notes="",
    aws_account_id=None,
    client_name=None,
    role_arn=None,
    cloud_provider="AWS",
    azure_subscription_id=None,
    azure_tenant_id=None,
    azure_client_id=None,
):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    normalized_provider = (
        str(cloud_provider or "AWS").strip() or "AWS"
    )

    cursor.execute("""
    SELECT id
    FROM remediation_actions
    WHERE finding = ?
      AND action_type = ?
      AND COALESCE(aws_account_id, '') = COALESCE(?, '')
      AND COALESCE(cloud_provider, 'AWS') = ?
      AND COALESCE(azure_subscription_id, '') = COALESCE(?, '')
      AND execution_status NOT IN ('Completed', 'Failed')
    ORDER BY id DESC
    LIMIT 1
    """, (
        finding,
        action_type,
        aws_account_id,
        normalized_provider,
        azure_subscription_id,
    ))

    existing_action = cursor.fetchone()

    if existing_action:
        conn.close()

        return {
            "action_id": existing_action[0],
            "created": False,
            "message": "Existing open action reused."
        }

    cursor.execute("""
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
        role_arn,
        cloud_provider,
        azure_subscription_id,
        azure_tenant_id,
        azure_client_id
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(datetime.now(UTC)),
        finding,
        action_type,
        priority,
        "Pending Approval",
        "Not Started",
        "Simulation",
        notes,
        aws_account_id,
        client_name,
        role_arn,
        normalized_provider,
        azure_subscription_id,
        azure_tenant_id,
        azure_client_id,
    ))

    action_id = cursor.lastrowid

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="ACTION_CREATED",
        event_detail=f"Created remediation action: {action_type}",
        actor="DGS Sentinel AI"
    )

    return {
        "action_id": action_id,
        "created": True,
        "message": "New remediation action created."
    }


def get_execution_actions():
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
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
        role_arn,
        adapter,
        resource_id,
        request_id,
        verification_request_id,
        verification_status,
        result_message,
        executed_at,
        evidence_hash,
        evidence_authentication_type,
        evidence_key_id,
        cloud_provider,
        azure_subscription_id,
        azure_tenant_id,
        azure_client_id
    FROM remediation_actions
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows


def update_execution_action(action_id, approval_status=None, execution_status=None):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT approval_status, execution_status
    FROM remediation_actions
    WHERE id = ?
    """, (action_id,))

    current_action = cursor.fetchone()

    if not current_action:
        conn.close()
        raise ValueError(f"Action ID {action_id} was not found.")

    current_approval, current_execution = current_action

    requested_approval = approval_status or current_approval
    requested_execution = execution_status or current_execution

    if current_execution == "Completed":
        if requested_execution != "Completed":
            conn.close()
            raise ValueError(
                "Completed actions cannot move backward to an earlier execution status."
            )

        if requested_approval != "Approved":
            conn.close()
            raise ValueError(
                "Completed actions must remain approved."
            )

    if (
        requested_execution in ["Ready", "Executing", "Completed"]
        and requested_approval != "Approved"
    ):
        conn.close()
        raise ValueError(
            "An action must be approved before it can move to Ready, Executing, or Completed."
        )

    cursor.execute("""
    UPDATE remediation_actions
    SET approval_status = ?,
        execution_status = ?
    WHERE id = ?
    """, (
        requested_approval,
        requested_execution,
        action_id
    ))

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="ACTION_UPDATED",
        event_detail=(
            f"Approval={requested_approval}, "
            f"Execution={requested_execution}"
        ),
        actor="DGS Sentinel AI"
    )

    return {
        "action_id": action_id,
        "approval_status": requested_approval,
        "execution_status": requested_execution
    }


def simulate_execution(action_id):
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        finding,
        action_type,
        approval_status,
        execution_status,
        execution_mode
    FROM remediation_actions
    WHERE id = ?
    """, (action_id,))

    action = cursor.fetchone()

    if not action:
        conn.close()
        raise ValueError(f"Action ID {action_id} was not found.")

    (
        _,
        finding,
        action_type,
        approval_status,
        execution_status,
        execution_mode
    ) = action

    controlled_result = execute_controlled_action(
        action_type=action_type,
        finding=finding,
        approval_status=approval_status,
        execution_mode="Simulation"
    )

    if controlled_result.get("status") != "SIMULATED":
        conn.close()
        raise ValueError(
            controlled_result.get(
                "message",
                "Simulation was blocked by remediation guardrails."
            )
        )

    cursor.execute("""
    UPDATE remediation_actions
    SET execution_status = ?
    WHERE id = ?
    """, (
        "Completed",
        action_id
    ))

    conn.commit()
    conn.close()

    log_remediation_event(
        action_id=action_id,
        event_type="CONTROLLED_SIMULATION_COMPLETED",
        event_detail=(
            f"Adapter={controlled_result.get('adapter')}; "
            f"Finding={finding}; "
            f"Action={action_type}; "
            f"Result={controlled_result.get('message')}"
        ),
        actor="DGS Sentinel AI"
    )

    return {
        "action_id": action_id,
        "status": "Completed",
        "mode": "Simulation",
        "adapter": controlled_result.get("adapter"),
        "finding": finding,
        "action_type": action_type,
        "message": controlled_result.get("message")
    }


def execute_live_action(
    action_id,
    expected_account_id=None,
    s3_client=None,
    confirmation_phrase="",
    actor="DGS Sentinel AI",
    expected_subscription_id=None,
    azure_storage_client=None,
    azure_network_client=None,
):
    """Execute one approved remediation action in guarded live mode."""

    init_execution_db()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            finding,
            action_type,
            approval_status,
            execution_status,
            aws_account_id,
            client_name,
            role_arn,
            cloud_provider,
            azure_subscription_id,
            azure_tenant_id,
            azure_client_id
        FROM remediation_actions
        WHERE id = ?
        """,
        (action_id,),
    )

    action = cursor.fetchone()

    if not action:
        connection.close()
        raise ValueError(
            f"Action ID {action_id} was not found."
        )

    (
        finding,
        action_type,
        approval_status,
        execution_status,
        bound_account_id,
        bound_client_name,
        bound_role_arn,
        bound_cloud_provider,
        bound_subscription_id,
        bound_tenant_id,
        bound_azure_client_id,
    ) = action

    is_azure_action = action_type in {
        "Generate Azure Storage Hardening Task",
        "Generate Azure NSG Rule Restriction Task",
    }

    is_azure_storage_action = (
        action_type == "Generate Azure Storage Hardening Task"
    )

    is_azure_nsg_action = (
        action_type == "Generate Azure NSG Rule Restriction Task"
    )

    if is_azure_action:
        if not bound_subscription_id:
            connection.close()
            raise ValueError(
                "This remediation action is not bound to an "
                "Azure subscription."
            )

        if str(bound_subscription_id) != str(
            expected_subscription_id
        ):
            connection.close()
            raise ValueError(
                "The selected Azure subscription does not match "
                "the subscription bound to this remediation action."
            )

    else:
        if not bound_account_id:
            connection.close()
            raise ValueError(
                "This remediation action is not bound to an AWS account."
            )

        if str(bound_account_id) != str(expected_account_id):
            connection.close()
            raise ValueError(
                "The selected AWS account does not match the "
                "account bound to this remediation action."
            )

    if approval_status != "Approved":
        connection.close()
        raise ValueError(
            "The remediation action must be approved "
            "before live execution."
        )

    if execution_status == "Completed":
        connection.close()
        raise ValueError(
            "This remediation action is already completed."
        )

    evidence_hmac_key = _get_evidence_hmac_key()
    evidence_key_id = _get_evidence_key_id(
        evidence_hmac_key
    )

    controlled_result = execute_controlled_action(
        action_type=action_type,
        finding=finding,
        approval_status=approval_status,
        execution_mode="Live",
        confirmation_phrase=confirmation_phrase,
        expected_account_id=(
            None if is_azure_action else expected_account_id
        ),
        s3_client=None if is_azure_action else s3_client,
        expected_subscription_id=(
            expected_subscription_id
            if is_azure_action
            else None
        ),
        azure_storage_client=(
            azure_storage_client
            if is_azure_storage_action
            else None
        ),
        azure_network_client=(
            azure_network_client
            if is_azure_nsg_action
            else None
        ),
    )

    result_status = controlled_result.get("status")
    result_message = controlled_result.get(
        "message",
        "Live remediation did not complete.",
    )

    def build_evidence(execution_status_value, executed_at_value):
        return _build_execution_evidence(
            action_id=action_id,
            finding=finding,
            action_type=action_type,
            approval_status=approval_status,
            execution_status=execution_status_value,
            execution_mode="Live",
            aws_account_id=bound_account_id,
            client_name=bound_client_name,
            role_arn=bound_role_arn,
            adapter=controlled_result.get("adapter"),
            resource_id=controlled_result.get("resource_id"),
            request_id=controlled_result.get("request_id"),
            verification_request_id=controlled_result.get(
                "verification_request_id"
            ),
            verification_status=controlled_result.get(
                "verification_status"
            ),
            result_message=result_message,
            executed_at=executed_at_value,
        )

    if (
        result_status == "EXECUTED"
        and controlled_result.get("verification_status") != "VERIFIED"
    ):
        executed_at = str(datetime.now(UTC))
        evidence_hash = _calculate_execution_evidence_hash(
            build_evidence("Failed", executed_at),
            evidence_hmac_key,
        )

        cursor.execute(
            """
            UPDATE remediation_actions
            SET execution_status = ?,
                execution_mode = ?,
                adapter = ?,
                resource_id = ?,
                request_id = ?,
                verification_request_id = ?,
                verification_status = ?,
                result_message = ?,
                executed_at = ?,
                evidence_hash = ?,
                evidence_authentication_type = ?,
                evidence_key_id = ?
            WHERE id = ?
            """,
            (
                "Failed",
                "Live",
                controlled_result.get("adapter"),
                controlled_result.get("resource_id"),
                controlled_result.get("request_id"),
                controlled_result.get("verification_request_id"),
                controlled_result.get("verification_status"),
                result_message,
                executed_at,
                evidence_hash,
                EVIDENCE_AUTHENTICATION_TYPE,
                evidence_key_id,
                action_id,
            ),
        )

        connection.commit()

        log_remediation_event(
            action_id=action_id,
            event_type="LIVE_REMEDIATION_VERIFICATION_FAILED",
            event_detail=(
                f"Adapter={controlled_result.get('adapter')}; "
                f"Finding={finding}; "
                f"Action={action_type}; "
                f"ResourceID={controlled_result.get('resource_id')}; "
                f"RequestID={controlled_result.get('request_id')}; "
                f"VerificationRequestID="
                f"{controlled_result.get('verification_request_id')}; "
                f"Result={result_message}"
            ),
            actor=actor,
        )

        connection.close()
        raise ValueError(result_message)

    if result_status != "EXECUTED":
        if result_status == "FAILED":
            executed_at = str(datetime.now(UTC))
            evidence_hash = _calculate_execution_evidence_hash(
                build_evidence("Failed", executed_at)
            )

            cursor.execute(
                """
                UPDATE remediation_actions
                SET execution_status = ?,
                    execution_mode = ?,
                    adapter = ?,
                    resource_id = ?,
                    request_id = ?,
                    verification_request_id = ?,
                    verification_status = ?,
                    result_message = ?,
                    executed_at = ?,
                    evidence_hash = ?,
                    evidence_authentication_type = ?,
                    evidence_key_id = ?
                WHERE id = ?
                """,
                (
                    "Failed",
                    "Live",
                    controlled_result.get("adapter"),
                    controlled_result.get("resource_id"),
                    controlled_result.get("request_id"),
                    controlled_result.get("verification_request_id"),
                    controlled_result.get("verification_status"),
                    result_message,
                    executed_at,
                    evidence_hash,
                    EVIDENCE_AUTHENTICATION_TYPE,
                    evidence_key_id,
                    action_id,
                ),
            )

            connection.commit()

            log_remediation_event(
                action_id=action_id,
                event_type="LIVE_REMEDIATION_FAILED",
                event_detail=(
                    f"Adapter={controlled_result.get('adapter')}; "
                    f"Finding={finding}; "
                    f"Action={action_type}; "
                    f"Result={result_message}"
                ),
                actor=actor,
            )

        else:
            log_remediation_event(
                action_id=action_id,
                event_type="LIVE_REMEDIATION_BLOCKED",
                event_detail=(
                    f"Finding={finding}; "
                    f"Action={action_type}; "
                    f"Result={result_message}"
                ),
                actor=actor,
            )

        connection.close()
        raise ValueError(result_message)

    executed_at = str(datetime.now(UTC))
    evidence_hash = _calculate_execution_evidence_hash(
        build_evidence("Completed", executed_at),
        evidence_hmac_key,
    )

    cursor.execute(
        """
        UPDATE remediation_actions
        SET execution_status = ?,
            execution_mode = ?,
            adapter = ?,
            resource_id = ?,
            request_id = ?,
            verification_request_id = ?,
            verification_status = ?,
            result_message = ?,
            executed_at = ?,
            evidence_hash = ?,
            evidence_authentication_type = ?,
            evidence_key_id = ?
        WHERE id = ?
        """,
        (
            "Completed",
            "Live",
            controlled_result.get("adapter"),
            controlled_result.get("resource_id"),
            controlled_result.get("request_id"),
            controlled_result.get("verification_request_id"),
            controlled_result.get("verification_status"),
            result_message,
            executed_at,
            evidence_hash,
            EVIDENCE_AUTHENTICATION_TYPE,
            evidence_key_id,
            action_id,
        ),
    )

    connection.commit()
    connection.close()

    log_remediation_event(
        action_id=action_id,
        event_type="LIVE_REMEDIATION_COMPLETED",
        event_detail=(
            f"Adapter={controlled_result.get('adapter')}; "
            f"Finding={finding}; "
            f"Action={action_type}; "
            f"Resource={controlled_result.get('resource_id')}; "
            f"RequestId={controlled_result.get('request_id')}; "
            f"Result={result_message}"
        ),
        actor=actor,
    )

    return {
        "action_id": action_id,
        "status": "Completed",
        "mode": "Live",
        "adapter": controlled_result.get("adapter"),
        "finding": finding,
        "action_type": action_type,
        "resource_id": controlled_result.get(
            "resource_id"
        ),
        "request_id": controlled_result.get(
            "request_id"
        ),
        "message": result_message,
    }

def verify_execution_evidence(
    action_id,
    actor="DGS Sentinel AI",
):
    init_execution_db()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
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
            evidence_hash,
            evidence_authentication_type,
            evidence_key_id
        FROM remediation_actions
        WHERE id = ?
        """,
        (action_id,),
    )

    row = cursor.fetchone()
    connection.close()

    if not row:
        raise ValueError(
            f"Action ID {action_id} was not found."
        )

    (
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
        stored_hash,
        authentication_type,
        stored_key_id,
    ) = row

    evidence = _build_execution_evidence(
        action_id=action_id,
        finding=finding,
        action_type=action_type,
        approval_status=approval_status,
        execution_status=execution_status,
        execution_mode=execution_mode,
        aws_account_id=aws_account_id,
        client_name=client_name,
        role_arn=role_arn,
        adapter=adapter,
        resource_id=resource_id,
        request_id=request_id,
        verification_request_id=verification_request_id,
        verification_status=verification_status,
        result_message=result_message,
        executed_at=executed_at,
    )

    calculated_hash = None

    if not stored_hash:
        integrity_status = "MISSING"

    elif authentication_type != EVIDENCE_AUTHENTICATION_TYPE:
        integrity_status = "UNSUPPORTED"

    else:
        matching_key = None

        for verification_key in _get_evidence_verification_keys():
            if (
                _get_evidence_key_id(verification_key)
                == stored_key_id
            ):
                matching_key = verification_key
                break

        if matching_key is None:
            integrity_status = "KEY_MISMATCH"

        else:
            calculated_hash = _calculate_execution_evidence_hash(
                evidence,
                matching_key,
            )

            if hmac.compare_digest(
                stored_hash,
                calculated_hash,
            ):
                integrity_status = "VERIFIED"

            else:
                integrity_status = "TAMPERED"

    log_remediation_event(
        action_id=action_id,
        event_type=(
            "REMEDIATION_EVIDENCE_VERIFICATION_"
            f"{integrity_status}"
        ),
        event_detail=(
            f"Status={integrity_status}; "
            f"AuthenticationType={authentication_type or 'Not Recorded'}; "
            f"KeyID={stored_key_id or 'Not Recorded'}"
        ),
        actor=actor,
    )

    return {
        "action_id": action_id,
        "status": integrity_status,
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "authentication_type": authentication_type,
        "key_id": stored_key_id,
    }


def create_actions_from_remediation_plan(
    remediation_plan,
    aws_account_id=None,
    client_name=None,
    role_arn=None,
    cloud_provider="AWS",
    azure_subscription_id=None,
    azure_tenant_id=None,
    azure_client_id=None,
):
    created_actions = []

    normalized_provider = (
        str(cloud_provider or "AWS").strip() or "AWS"
    )

    for item in remediation_plan:
        category = item.get("category", "Monitoring")
        finding = item.get("finding", "Unknown Finding")
        priority = item.get("priority", "STANDARD")

        if category == "Identity & Access":
            action_type = (
                "Generate IAM MFA and Access Key Review Task"
            )

        elif category == "Azure Storage":
            action_type = (
                "Generate Azure Storage Hardening Task"
            )

        elif category == "Azure Network":
            action_type = (
                "Generate Azure NSG Rule Restriction Task"
            )

        elif category == "Data Exposure":
            action_type = (
                "Generate S3 Exposure Remediation Task"
            )

        elif category == "Threat Detection":
            action_type = (
                "Generate Incident Response Investigation Task"
            )

        elif category == "Security Posture":
            action_type = (
                "Generate Cloud Security Posture Remediation Task"
            )

        else:
            action_type = "Generate Monitoring Review Task"

        create_execution_action(
            finding=finding,
            action_type=action_type,
            priority=priority,
            notes=(
                "Automatically generated from DGS Sentinel AI "
                "remediation plan. Human approval required before "
                "live execution."
            ),
            aws_account_id=aws_account_id,
            client_name=client_name,
            role_arn=role_arn,
            cloud_provider=normalized_provider,
            azure_subscription_id=azure_subscription_id,
            azure_tenant_id=azure_tenant_id,
            azure_client_id=azure_client_id,
        )

        created_actions.append(
            {
                "finding": finding,
                "action_type": action_type,
                "priority": priority,
                "aws_account_id": aws_account_id,
                "client_name": client_name,
                "role_arn": role_arn,
                "cloud_provider": normalized_provider,
                "azure_subscription_id": (
                    azure_subscription_id
                ),
                "azure_tenant_id": azure_tenant_id,
                "azure_client_id": azure_client_id,
            }
        )

    return created_actions


def simulate_all_approved_actions():
    init_execution_db()

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id
    FROM remediation_actions
    WHERE approval_status = 'Approved'
      AND execution_status NOT IN ('Completed', 'Failed')
    ORDER BY id
    """)

    action_ids = [
        row[0]
        for row in cursor.fetchall()
    ]

    conn.close()

    results = []

    for action_id in action_ids:
        try:
            result = simulate_execution(action_id)
            results.append(result)

        except Exception as e:
            results.append({
                "action_id": action_id,
                "status": "Failed",
                "message": str(e)
            })

            update_execution_action(
                action_id=action_id,
                execution_status="Failed"
            )

    return results
