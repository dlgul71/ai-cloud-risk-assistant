# ADR-0001: Database and Migration Strategy

**Status:** Accepted for Phase 1; storage, backup inventory, registry inspection, and fresh-schema recognition implemented; adoption/apply pending
**Decision date:** September 9, 2026
**Decision owners:** DGS Sentinel AI maintainers
**Applies to:** Persistent application data and schema evolution

## Context

DGS Sentinel AI currently stores persistent data across multiple SQLite databases.

Known database domains include:

| Database | Primary responsibility |
| --- | --- |
| `assets.db` | Tenant-scoped assets and scan results |
| `clients.db` | Client accounts and cloud connection metadata |
| `remediation.db` | Remediation items, approvals, execution, and evidence |
| `operational_monitoring.db` | Health and operational-monitoring records |
| `users.db` | Persistent users, authentication events, and access assignments |
| `ai_assets.db` | Tenant-scoped AI asset and relationship data |
| `caasm_alerts.db` | CAASM correlated-exposure alerts |
| `dgs_sentinel.db` | Legacy headless scan findings |
| `remediation_actions.db` | Execution actions, evidence, and remediation audit events |

Most database paths use the centralized `DGS_DATA_DIR` storage location.

At the decision date, `caasm_alert_db.py` used a relative path. The September 30 storage update routes its default `caasm_alerts.db` path through `DGS_DATA_DIR` and retains explicit test overrides. Existing files require controlled relocation; see [CAASM alert storage](../operations/CAASM-ALERT-STORAGE.md).

The scan-findings store (`dgs_sentinel.db`) and both execution/audit modules for `remediation_actions.db` now use the shared storage helper. With DGS_DATA_DIR unset, working-directory defaults remain compatible; explicit DB_NAME overrides remain supported. Deployment-specific relocation and backup verification are still required.

See [the database inventory](DATABASE-INVENTORY.md) for all nine SQLite files, fresh schema definitions, inline upgrade behavior, and default backup coverage.

Current schema behavior includes:

- Runtime `CREATE TABLE IF NOT EXISTS` operations.
- Inline `ALTER TABLE` operations.
- Module-specific schema initialization.
- Module-specific indexes.
- Registry contract and read-only inspection are defined; existing databases have not been adopted.
- No formal ordered migration framework.
- No consistent migration audit record.
- No automated compatibility check between application and database versions.
- No controlled multi-database migration transaction.
- No approved production-scale persistence architecture.

The platform already contains tenant-scoped security controls. Any persistence change must preserve tenant boundaries, authorization, evidence integrity, and recovery capability.

## Problem

Runtime table creation and inline schema changes are useful during early development but create increasing operational risk.

Without formal migration controls:

- Existing installations may have different schemas.
- A deployment may change data before rollback readiness is known.
- Application rollback may be incompatible with upgraded databases.
- Partial upgrades may leave databases in inconsistent states.
- Schema changes may not be represented in release evidence.
- Backup scope may not match migration scope.
- Tenant keys, indexes, constraints, or audit data may be lost.
- Multiple application instances may attempt schema changes concurrently.
- Operators cannot reliably determine database compatibility before startup.

A production-oriented platform requires deterministic, reviewable, testable, and recoverable schema evolution.

## Decision

DGS Sentinel AI will use a staged persistence strategy.

### 1. Retain SQLite During Phase 1 Stabilization

The existing SQLite databases will remain in place during Phase 1 stabilization.

This decision avoids combining:

- Application stabilization.
- Schema-framework implementation.
- Data migration.
- Infrastructure provisioning.
- Production datastore replacement.

Retaining SQLite during Phase 1 does not approve SQLite as the final production-scale multi-tenant datastore.

### 2. Do Not Add Another Database File Without Architecture Review

New persistent domains must use an existing database when technically and security appropriate.

A new database file requires:

- A documented use case.
- Tenant-isolation analysis.
- Backup and restoration design.
- Retention requirements.
- Encryption requirements.
- Schema ownership.
- Migration ownership.
- Operational-health requirements.
- Architecture approval.

### 3. Centralize All Database Paths

Every SQLite database must resolve through the centralized storage-path layer.

The future implementation must:

- Use `DGS_DATA_DIR`.
- Reject unsafe or ambiguous paths.
- Preserve simple database filenames.
- Support test-specific path overrides.
- Work inside the hardened container’s `/data` volume.
- Avoid writing persistent data to the application directory.

CAASM alert path centralization is implemented with unit tests and a read-only-container persistence check. This path correction does not add tenant boundaries or versioned schema migrations to CAASM alerts.

### 4. Introduce Versioned Migrations Per Database Domain

Each database will maintain its own ordered migration history because the current domains are stored in separate files.

Each database will contain a migration registry with fields equivalent to:

| Field | Purpose |
| --- | --- |
| `version` | Monotonically increasing schema version |
| `name` | Stable migration name |
| `checksum` | Detects modification of an applied migration |
| `applied_at` | UTC application timestamp |
| `application_version` | Application release applying the migration |

The registry contract is now defined as `schema_migrations` with `version`, `name`, `checksum`, `applied_at`, and `application_version`; see [read-only migration status](../operations/DATABASE-MIGRATION-STATUS.md). No registry is initialized or populated automatically.

Migration files will be:

- Ordered.
- Immutable after release.
- Idempotent where practical.
- Reviewed as application code.
- Bound to one database domain.
- Accompanied by tests.
- Included in release and rollback planning.

An applied migration must never be silently edited. Corrections require a new migration.

### 5. Separate Schema Migration From Normal Application Startup

The application must not silently perform consequential schema upgrades during ordinary startup.

The future migration interface will provide separate operations equivalent to:

- Status.
- Compatibility check.
- Migration plan.
- Apply.
- Verification.

The read-only command `python -m scripts.database_migrations_cli status` is implemented. Plan, apply, verification, baseline adoption, and startup compatibility enforcement remain pending. No domain has an approved migration catalog yet.

After the migration framework is introduced, application startup should:

1. Open databases safely.
2. Read their schema versions.
3. Confirm compatibility with the application release.
4. Refuse startup when a schema is unknown, partially migrated, corrupted, or newer than supported.
5. Provide a useful error without exposing sensitive data.

Automatic migration will remain disabled by default.

### 6. Establish Existing-Database Baselines Safely

Existing databases cannot be marked as migrated merely because a file exists.

Baseline adoption must:

1. Create and verify a complete backup.
2. Inspect required tables, columns, indexes, and constraints.
3. Determine the verified legacy schema state. The read-only `baseline` command recognizes only reviewed current fresh shapes; historical variants and data invariants still require separate review.
4. Reject unknown or ambiguous schemas.
5. Record the approved baseline version.
6. Preserve existing tenant identifiers and relationships.
7. Verify record counts and integrity.
8. Produce migration evidence.

A baseline marker must not conceal an unsupported schema.

### 7. Use Controlled Migration Execution

Migration execution must:

- Require an explicit operator action.
- Identify the target environment.
- Identify the application release.
- Identify every database in scope.
- Confirm backup verification.
- Confirm available storage.
- Prevent concurrent migrators.
- Use bounded database timeouts.
- Use transactions where SQLite supports the required operation.
- Stop on the first failure.
- Preserve the original error cause.
- Avoid logging sensitive data.
- Record completed and failed migration evidence.
- Verify the final schema.
- Leave the application stopped when compatibility cannot be established.

Because the platform uses multiple database files, a transaction cannot make all database migrations globally atomic. Release planning must account for partial multi-database failure.

### 8. Require Explicit Preconditions

A migration must not begin unless:

- The target commit is approved.
- Required CI checks passed.
- The working tree is clean.
- The target data directory is explicit.
- Database inventory is complete.
- Backup scope includes every affected database.
- Backup verification passed.
- Restore capability was tested.
- Required disk capacity is available.
- No other migrator is active.
- Application traffic is stopped when required.
- Tenant impact is documented.
- Rollback criteria are approved.

### 9. Preserve Tenant Isolation

Schema migrations affecting tenant-scoped data must verify:

- Tenant keys remain populated.
- Tenant keys remain stable.
- Tenant ownership cannot be reassigned accidentally.
- Unique constraints include tenant scope where required.
- Indexes support tenant-filtered queries.
- Foreign-key relationships do not cross tenants incorrectly.
- Backfills cannot copy one tenant’s data into another tenant.
- Default values cannot create global access accidentally.
- Negative tenant-access tests continue to pass.
- Exports and AI context remain tenant-scoped.

A migration that cannot prove tenant safety must not be released.

### 10. Preserve Authentication and Authorization

Migrations affecting `users.db` must preserve:

- Password hashes.
- User activation status.
- Global-administrator restrictions.
- Normalized roles.
- Client-access assignments.
- Account-lockout state where operationally required.
- Authentication audit events.
- Session-security expectations.

Plaintext passwords must never be introduced into migration data, logs, fixtures, or evidence.

### 11. Preserve Remediation Evidence

Migrations affecting `remediation.db` must preserve:

- Approval and execution separation.
- Action identifiers.
- Execution outcomes.
- Evidence integrity fields.
- HMAC verification data.
- Key identifiers.
- Historical-key verification.
- Failure evidence.
- Audit chronology.
- Tenant ownership.

Migration activity must not be allowed to make failed or unauthorized remediation appear successful.

### 12. Define Rollback by Data Risk

Schema rollback will not rely automatically on reverse migrations.

The preferred rollback method for destructive or incompatible changes is:

1. Stop the application.
2. Preserve the failed database state.
3. Verify the predeployment backup.
4. Restore into an empty recovery location.
5. Verify database integrity and tenant data.
6. Start the compatible prior application release.
7. Run authentication, authorization, tenant-isolation, and smoke tests.

A reverse migration may be used only when:

- It is explicitly implemented.
- It is nondestructive or its data impact is approved.
- It has targeted tests.
- It has been rehearsed using production-representative data.
- Backup-based recovery remains available.

Application rollback without database compatibility verification is prohibited.

### 13. Require Migration Testing

Every schema change must include applicable tests for:

- Fresh database initialization.
- Upgrade from the immediately previous supported version.
- Upgrade from every supported baseline.
- Repeated execution or idempotency.
- Existing data preservation.
- Tenant isolation.
- Constraint enforcement.
- Index creation.
- Invalid or unknown schema rejection.
- Partial-failure behavior.
- Backup before migration.
- Restoration after migration.
- Application compatibility.
- Failure evidence.
- Concurrent migration prevention.

Destructive migrations require additional record-count, integrity, and rollback verification.

### 14. Document Every Schema Change

Each schema-changing pull request must document:

- Database domain.
- Current version.
- Target version.
- Migration purpose.
- Tables, columns, indexes, and constraints affected.
- Data backfill behavior.
- Tenant impact.
- Authentication impact.
- Remediation-evidence impact.
- Backup requirements.
- Deployment ordering.
- Expected duration.
- Rollback procedure.
- Test evidence.
- Known limitations.

Release notes must identify schema compatibility requirements.

### 15. Evaluate a Production Datastore Separately

Before a controlled customer pilot or production-scale claim, DGS must evaluate a managed production datastore such as PostgreSQL.

The evaluation must consider:

- Tenant-isolation model.
- Transaction and concurrency requirements.
- Connection management.
- High availability.
- Backup and point-in-time recovery.
- Encryption at rest and in transit.
- Key management.
- Audit logging.
- Schema migration support.
- Operational monitoring.
- Regional availability.
- Disaster recovery.
- Recovery-time objective.
- Recovery-point objective.
- Cost.
- Administrative burden.
- Data migration complexity.
- Local development and test experience.

A future datastore selection requires a separate ADR.

## Proposed Migration Structure

The implementation should use one shared migration engine with domain-specific ordered migrations.

A possible structure is:

```text
database_migrations/
├── assets/
├── clients/
├── remediation/
├── operational_monitoring/
├── users/
├── ai_assets/
└── caasm_alerts/
```

The shared `database_migrations` package and status CLI are implemented. The domain subdirectories and ordered migration files shown above remain illustrative and unimplemented; all reviewed catalogs are currently empty.

The migration engine should own:

- Discovery.
- Ordering.
- Checksum verification.
- Compatibility checks.
- Execution locking.
- Evidence generation.
- Failure reporting.
- Post-migration verification.

Database modules should retain domain query responsibilities but should no longer own untracked schema evolution.

## Migration Locking

SQLite supports file-level coordination but does not provide a cross-database migration transaction.

The future implementation must use a deliberate migration lock that:

- Has one documented location under `DGS_DATA_DIR`.
- Identifies the operator and process.
- Includes a creation timestamp.
- Prevents multiple migration processes.
- Handles stale locks through an explicit recovery procedure.
- Does not silently delete an active lock.

Application instances must remain stopped when a migration requires exclusive access.

## Schema Compatibility Policy

Each application release will declare the schema versions it supports.

The compatibility check must distinguish:

| Condition | Required behavior |
| --- | --- |
| Expected version | Application may start |
| Older supported version | Migration required before startup |
| Older unsupported version | Stop and require controlled upgrade planning |
| Newer version | Stop to prevent incompatible downgrade |
| Missing registry on recognized legacy schema | Require controlled baseline adoption |
| Missing registry on unknown schema | Stop and investigate |
| Partial migration | Stop and recover |
| Checksum mismatch | Stop and investigate possible drift |
| Integrity failure | Stop and begin recovery |

## Backup Requirements

Migration backup scope must include every database affected by the release, not merely the current default set.

Backup and health defaults now share an inventory covering all nine SQLite
databases under DGS_DATA_DIR. Explicit database lists and module path overrides
must be reviewed against the actual deployment. Legacy working-directory copies
pending relocation and additional persistent files remain outside that default.

Missing files are reported as warnings and are not initialized by backup/health
checks. Verification and restoration cover packaged files only; a successful
verification does not establish that missing databases were optional for a
specific deployment. Review the manifest and rehearse complete restoration.
See [SQLite backup and health coverage](../operations/SQLITE-BACKUP-HEALTH.md).

Backup completion alone is insufficient. Verification and restoration must also succeed.

## Security Requirements

Migration code must:

- Use parameterized queries for data values.
- Avoid unsafe dynamic SQL.
- Allow only reviewed migration identifiers.
- Avoid logging row content unless specifically approved.
- Avoid logging credentials, tokens, password hashes, or sensitive evidence.
- Validate filesystem paths.
- Preserve file ownership and permissions.
- Produce auditable outcomes.
- Fail closed on compatibility uncertainty.
- Keep live remediation disabled during migration.
- Treat imported or transformed data as untrusted.
- Bound retries and timeouts.

## Operational Evidence

A migration execution record should include:

- Environment.
- Application release.
- Commit SHA.
- Database domain.
- Source schema version.
- Target schema version.
- Migration names and checksums.
- Start and completion timestamps.
- Operator.
- Backup ID.
- Outcome.
- Verification results.
- Failure category when applicable.

The record must not contain secrets or unnecessary client data.

## Consequences

### Positive

- Deterministic schema evolution.
- Clear application and database compatibility.
- Reviewable migration history.
- Stronger tenant-safety assurance.
- Better backup and rollback planning.
- Reduced dependence on runtime `ALTER TABLE` behavior.
- Improved deployment evidence.
- Safer future transition to a managed datastore.

### Negative

- Additional implementation and testing effort.
- More controlled deployment steps.
- Required maintenance windows for some SQLite changes.
- Cross-database migrations cannot be globally atomic.
- Existing databases require careful baseline adoption.
- Temporary coexistence with legacy runtime initialization will require disciplined sequencing.

### Risks

- Incorrect baseline recognition could certify an unsupported schema.
- Incomplete backup inventory could prevent full recovery.
- A partial multi-database migration could produce inconsistent application state.
- Concurrent application access could interfere with migration.
- Premature datastore replacement could expand risk during stabilization.

These risks are addressed through explicit compatibility checks, verified backups, exclusive execution, tenant tests, and phased implementation.

## Alternatives Considered

### Continue Runtime Schema Creation and Inline Alterations

Rejected as the long-term strategy.

This approach lacks deterministic ordering, version visibility, migration evidence, and reliable rollback planning.

### Move Immediately to PostgreSQL

Deferred.

A managed datastore may be appropriate, but immediate replacement would combine infrastructure, data conversion, application refactoring, and stabilization risks.

### Combine All SQLite Domains Into One File

Rejected for the current phase.

Combining domains would require a substantial migration without first establishing the migration controls needed to perform it safely.

### Adopt an ORM Without a Migration Framework

Rejected as insufficient.

An ORM can improve data access but does not independently provide ordered migration history, compatibility enforcement, backup verification, or operational evidence.

### Require Reverse Migrations for Every Change

Rejected as a universal rule.

Reverse migrations can destroy data or create false confidence. Verified backup restoration is the preferred recovery path for destructive changes.

## Implementation Sequence

1. Correct CAASM alert storage to use `DGS_DATA_DIR` — implemented September 30, 2026; existing-data relocation remains an operator action.
2. Document the existing schema for every database — the code-derived inventory is available; deployed schema validation and formal baseline adoption remain pending.
3. Define the migration registry schema — contract implemented; no deployed registry adoption.
4. Implement migration discovery and checksum validation — immutable descriptors and history/checksum inspection implemented; approved domain migrations and filesystem discovery remain pending.
5. Implement schema compatibility checks.
6. Implement explicit status, plan, apply, and verify operations — read-only status implemented; other operations remain pending.
7. Add migration locking.
8. Add fresh-database tests.
9. Add existing-database baseline adoption — strict read-only fresh-schema recognition implemented; historical recognition and controlled adoption remain pending.
10. Convert inline schema changes into ordered migrations.
11. Validate complete deployment backup scope (all nine SQLite defaults are now included).
12. Add migration and restoration CI tests.
13. Rehearse migration using production-representative test data.
14. Update deployment and release procedures.
15. Evaluate the production datastore in a separate ADR.

## Acceptance Criteria

This decision is implemented when:

- All database paths are centralized.
- Every database has a recognized schema version.
- Existing schemas can be validated before baseline adoption.
- Ordered migrations are immutable and checksum-verified.
- Consequential migrations require explicit operator action.
- Concurrent migration is prevented.
- Application startup enforces schema compatibility.
- Fresh and upgraded databases are tested.
- Tenant boundaries are verified after migration.
- Authentication and remediation evidence are preserved.
- Backup and restoration cover every affected database.
- Migration outcomes produce safe operational evidence.
- Inline untracked schema evolution is retired.
- Deployment and release documentation reflect the migration workflow.

## Follow-Up Decisions

Separate decisions are still required for:

- Final production datastore selection.
- Managed database hosting.
- High-availability design.
- Encryption and key-management architecture.
- Retention and archival policy.
- Recovery-time and recovery-point objectives.
- Disaster-recovery architecture.

Execution and audit storage now share the DGS_DATA_DIR default, with regressions for SQLite backup relocation, unchanged records and signed evidence, and read-only-container persistence. See [execution and audit storage](../operations/REMEDIATION-ACTIONS-STORAGE.md). Existing databases require explicit relocation; the default backup inventory now includes remediation_actions.db. This path change does not implement schema versioning or certify any production cutover.

Read-only fresh-schema recognition covers all nine domains through reviewed definition checksums and schema fingerprints, including triggers and constraints. See [baseline recognition](../operations/DATABASE-BASELINE-RECOGNITION.md). Recognition is not data certification or version adoption; no migration catalog or startup compatibility enforcement is enabled by this step.
