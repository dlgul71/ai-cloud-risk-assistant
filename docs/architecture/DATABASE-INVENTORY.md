# SQLite database inventory and schema baseline

Reviewed September 30, 2026 against main commit 3b457a0 and the accompanying
shared backup/health inventory update. This is a code-derived inventory of fresh
schemas, not certification of a deployed database or an adopted migration
baseline. Existing installations may differ after legacy inline upgrades.
A shared registry contract and read-only history/checksum inspector now exist,
but no domain has an approved migration catalog or an adopted version registry.
See [migration status](../operations/DATABASE-MIGRATION-STATUS.md).

## Persistent database inventory

| Database | Owning modules | Default location | Default backup and health coverage | Scope notes |
| --- | --- | --- | --- | --- |
| `assets.db` | [`asset_db.py`](../../asset_db.py) | DGS_DATA_DIR | Yes | Tenant and asset composite primary key. |
| `clients.db` | [`client_db.py`](../../client_db.py) | DGS_DATA_DIR | Yes | Unique client key; cloud connection metadata. |
| `remediation.db` | [`remediation_db.py`](../../remediation_db.py) | DGS_DATA_DIR | Yes | Tenant remediation items; legacy rows assigned a quarantine key. |
| `operational_monitoring.db` | [`operational_monitoring.py`](../../operational_monitoring.py) | DGS_DATA_DIR | Yes | Health runs carry client keys; results reference their run. |
| `users.db` | [`user_db.py`](../../user_db.py) | DGS_DATA_DIR | Yes | Users, access assignments, lockout state, and authentication audit. |
| `ai_assets.db` | [`ai_asset_db.py`](../../ai_asset_db.py) | DGS_DATA_DIR | Yes | Tenant composite keys; relationships have no declared foreign keys. |
| `caasm_alerts.db` | [`caasm_alert_db.py`](../../caasm_alert_db.py) | DGS_DATA_DIR | Yes | Global fingerprint uniqueness; no client_key column. |
| `dgs_sentinel.db` | [`db.py`](../../db.py) | DGS_DATA_DIR | Yes | Legacy scan findings; no tenant or account identifier. |
| `remediation_actions.db` | [`remediation_execution.py`](../../remediation_execution.py), [`remediation_audit.py`](../../remediation_audit.py) | DGS_DATA_DIR | Yes | Execution and audit records; no client_key column. |

DGS_DATA_DIR paths use the shared storage helper and resolve at call time.
When DGS_DATA_DIR is unset, that helper preserves working-directory behavior.
Explicit module path overrides remain supported. Operational monitoring also
supports a per-call path. Configured storage must be provisioned writable by
the runtime user; modules do not all create missing directories identically.

## Backup and recovery scope

Backup and health defaults share storage_paths.SQLITE_DATABASE_NAMES and resolve
all nine paths under DGS_DATA_DIR at call time. Existing explicit backup lists
and health DATABASE_FILES overrides still replace the default scope. Module
DB_NAME overrides and legacy working-directory copies require explicit paths;
the inventory does not discover arbitrary external files.

Missing files produce backup/health WARN results and are not created. Backup
manifests list missing_databases; the create CLI returns 2 when files are missing.
Verification and restore validate only files recorded in the package, so a PASS
does not establish that every database required by a deployment was captured.
An empty package fails verification and cannot be restored. Review missing
files and rehearse restoration before accepting a backup for recovery.
See [SQLite backup and health coverage](../operations/SQLITE-BACKUP-HEALTH.md).

SQLite databases are not the entire persistence inventory. Snapshot history,
client scan results, CAASM snapshot files, logs, configuration, and evidence
signing keys need their own backup and recovery scope. Never include signing
keys in public migration evidence.

## Legacy schema evolution

- assets: rebuilds a legacy asset-id-only table with a tenant/asset composite
  primary key; legacy rows receive __legacy_unassigned__.
- clients: adds cloud metadata and client keys, backfills missing keys, and
  creates a unique client-key index.
- remediation items: adds tenant/account and recurrence fields, backfills
  legacy tenant ownership, and creates tenant query indexes. Older upgraded
  tables may retain nullable columns even when fresh DDL declares NOT NULL.
- operational monitoring: adds client_key to historical health runs and
  assigns the system key where necessary.
- remediation actions: adds cloud, adapter, verification, and evidence fields
  through inline ALTER TABLE operations.
- users, AI assets, alerts, scan findings, and remediation audit: initialize
  tables and applicable indexes; no version registry certifies compatibility.

Do not mark a file as migrated merely because it exists or its table names
match. Inspect column type, nullability, defaults, primary and unique keys,
foreign keys, indexes, and data invariants before adopting any baseline.

## Fresh schema definitions

The definitions below are extracted from current static CREATE statements.
SQLite's implicit autoindexes and sqlite_sequence are omitted. Inline
migration outcomes must be inspected separately on upgraded databases.

### assets.db

Tables: `assets`.

```sql
CREATE TABLE IF NOT EXISTS assets (
    client_key TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    asset_type TEXT,
    account_id TEXT,
    region TEXT,
    hostname TEXT,
    ip_address TEXT,
    public_ip TEXT,
    state TEXT,
    risk_score INTEGER,
    last_scan TEXT,
    PRIMARY KEY (client_key, asset_id)
);
CREATE INDEX IF NOT EXISTS
idx_assets_client_key
ON assets(client_key);
CREATE INDEX IF NOT EXISTS
idx_assets_account_id
ON assets(account_id);
CREATE INDEX IF NOT EXISTS
idx_assets_client_risk
ON assets(client_key, risk_score DESC);
```

### clients.db

Tables: `clients`.

```sql
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_name TEXT,
    aws_account_id TEXT,
    role_arn TEXT,
    environment TEXT,
    cloud_provider TEXT DEFAULT 'AWS',
    azure_subscription_id TEXT,
    azure_tenant_id TEXT,
    azure_client_id TEXT,
    client_key TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS
idx_clients_client_key
ON clients(client_key);
```

### remediation.db

Tables: `remediation_items`.

```sql
CREATE TABLE IF NOT EXISTS remediation_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_key TEXT NOT NULL,
    created_at TEXT,
    category TEXT,
    priority TEXT,
    finding TEXT,
    recommendation TEXT,
    owner TEXT,
    status TEXT,
    risk_score INTEGER,
    aws_account_id TEXT,
    client_name TEXT,
    occurrence_count INTEGER DEFAULT 1,
    last_seen_at TEXT
);
CREATE INDEX IF NOT EXISTS
idx_remediation_client_key
ON remediation_items(client_key);
CREATE INDEX IF NOT EXISTS
idx_remediation_client_status
ON remediation_items(
    client_key,
    status,
    risk_score DESC
);
CREATE INDEX IF NOT EXISTS
idx_remediation_client_finding
ON remediation_items(
    client_key,
    aws_account_id,
    category,
    finding,
    status
);
```

### operational_monitoring.db

Tables: `health_runs`, `health_check_results`.

```sql
CREATE TABLE IF NOT EXISTS health_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_key TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    source TEXT NOT NULL,
    overall_status TEXT NOT NULL,
    pass_count INTEGER NOT NULL DEFAULT 0,
    warning_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    check_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS
health_check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    component TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT NOT NULL,
    FOREIGN KEY (run_id)
        REFERENCES health_runs(id)
        ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS
idx_health_runs_client_checked_at
ON health_runs(
    client_key,
    checked_at DESC
);
CREATE INDEX IF NOT EXISTS
idx_health_runs_client_status
ON health_runs(
    client_key,
    overall_status,
    checked_at DESC
);
CREATE INDEX IF NOT EXISTS
idx_health_results_component
ON health_check_results(
    component,
    checked_at DESC
);
CREATE INDEX IF NOT EXISTS
idx_health_results_run_id
ON health_check_results(run_id);
```

### users.db

Tables: `users`, `user_client_access`, `authentication_audit_events`.

```sql
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL
        COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active INTEGER NOT NULL
        DEFAULT 1,
    is_global_admin INTEGER NOT NULL
        DEFAULT 0,
    failed_login_attempts INTEGER
        NOT NULL DEFAULT 0,
    locked_until TEXT,
    password_changed_at TEXT NOT NULL,
    last_login_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (TRIM(username) <> ''),
    CHECK (
        role IN (
            'Administrator',
            'Analyst',
            'Viewer'
        )
    ),
    CHECK (
        is_active IN (0, 1)
    ),
    CHECK (
        is_global_admin IN (0, 1)
    ),
    CHECK (
        failed_login_attempts >= 0
    )
);
CREATE TABLE IF NOT EXISTS
user_client_access (
    user_id TEXT NOT NULL,
    client_key TEXT NOT NULL,
    granted_at TEXT NOT NULL,
    granted_by TEXT,
    PRIMARY KEY (
        user_id,
        client_key
    ),
    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE CASCADE,
    CHECK (
        TRIM(client_key) <> ''
    )
);
CREATE TABLE IF NOT EXISTS
authentication_audit_events (
    event_id INTEGER
        PRIMARY KEY AUTOINCREMENT,
    user_id TEXT,
    username TEXT,
    client_key TEXT,
    event_type TEXT NOT NULL,
    success INTEGER NOT NULL,
    occurred_at TEXT NOT NULL,
    details_json TEXT,
    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
        ON DELETE SET NULL,
    CHECK (
        TRIM(event_type) <> ''
    ),
    CHECK (
        success IN (0, 1)
    )
);
CREATE INDEX IF NOT EXISTS
idx_users_active_role
ON users(
    is_active,
    role
);
CREATE INDEX IF NOT EXISTS
idx_user_client_access_client
ON user_client_access(
    client_key,
    user_id
);
CREATE INDEX IF NOT EXISTS
idx_auth_events_occurred
ON authentication_audit_events(
    occurred_at DESC
);
CREATE INDEX IF NOT EXISTS
idx_auth_events_user
ON authentication_audit_events(
    user_id,
    occurred_at DESC
);
```

### ai_assets.db

Tables: `ai_assets`, `ai_asset_relationships`.

```sql
CREATE TABLE IF NOT EXISTS ai_assets (
    client_key TEXT NOT NULL,
    ai_asset_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT,
    environment TEXT,
    description TEXT,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (
        client_key,
        ai_asset_id
    )
);
CREATE TABLE IF NOT EXISTS ai_asset_relationships (
    client_key TEXT NOT NULL,
    source_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (
        client_key,
        source_asset_id,
        relationship_type,
        target_asset_id
    )
);
CREATE INDEX IF NOT EXISTS
idx_ai_assets_client_key
ON ai_assets(client_key);
CREATE INDEX IF NOT EXISTS
idx_ai_assets_type
ON ai_assets(asset_type);
CREATE INDEX IF NOT EXISTS
idx_ai_assets_client_risk
ON ai_assets(
    client_key,
    risk_score DESC
);
CREATE INDEX IF NOT EXISTS
idx_ai_relationships_client
ON ai_asset_relationships(client_key);
```

### caasm_alerts.db

Tables: `caasm_alerts`.

```sql
CREATE TABLE IF NOT EXISTS caasm_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_notified_at TEXT,
    alert_type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    priority TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    asset_id TEXT,
    hostname TEXT,
    asset_type TEXT,
    source TEXT,
    owner TEXT,
    risk_drivers TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    notification_count INTEGER NOT NULL DEFAULT 0,
    acknowledged_at TEXT,
    acknowledged_by TEXT,
    resolved_at TEXT,
    resolved_by TEXT,
    resolution_note TEXT
);
CREATE INDEX IF NOT EXISTS
idx_caasm_alerts_status_priority
ON caasm_alerts(status, priority, risk_score);
CREATE INDEX IF NOT EXISTS
idx_caasm_alerts_last_notified
ON caasm_alerts(last_notified_at);
```

### dgs_sentinel.db

Tables: `scan_findings`.

```sql
CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time TEXT,
    cve_id TEXT,
    priority TEXT,
    risk_score INTEGER,
    kev_exploited BOOLEAN,
    known_ransomware TEXT,
    required_action TEXT
);
```

### remediation_actions.db

Tables: `remediation_actions`, `remediation_audit`.

```sql
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
```

## Baseline adoption prerequisites

1. Stop writers and identify every resolved database path, including both
   working-directory stores and any explicit overrides.
2. Create a complete SQLite-consistent backup; verify it and rehearse restore
   into an empty location before touching production data.
3. Read sqlite_master and PRAGMA table_info, index_list, index_info, and
   foreign_key_list without invoking runtime initialization on an unknown
   production database.
4. Compare deployed schemas to reviewed baseline candidates and reject
   unknown or ambiguous combinations. Run integrity and foreign-key checks.
5. Verify record counts, tenant keys, access assignments, password hashes,
   execution statuses, evidence integrity fields, and audit chronology
   without exporting sensitive row values into migration evidence.
6. Adopt a version only after a recognized schema and its data invariants
   pass. The registry contract is defined; baseline recognition and adoption tooling
   are still pending.

## Remaining implementation work

- Verify deployment-specific relocation of historical records before changing
  DGS_DATA_DIR; runtime does not relocate legacy databases automatically.
- Verify deployment-specific backup scope, including path overrides and
  persistent files outside the default SQLite inventory.
- Approve domain migration catalogs and baseline recognition; then implement
  controlled adoption, plan/apply/verify, locking, and startup compatibility.
  Registry metadata checks and read-only status are implemented; they do not
  certify application schema or data compatibility.

See [ADR-0001](ADR-0001-DATABASE-MIGRATION-STRATEGY.md) for the migration
policy and [scan findings storage](../operations/SCAN-FINDINGS-STORAGE.md)
and [execution and audit storage](../operations/REMEDIATION-ACTIONS-STORAGE.md)
for cutover and rollback requirements.
