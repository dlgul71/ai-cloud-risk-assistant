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
    );

CREATE TABLE IF NOT EXISTS remediation_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT,
        action_id INTEGER,
        event_type TEXT,
        event_detail TEXT,
        actor TEXT
    );
