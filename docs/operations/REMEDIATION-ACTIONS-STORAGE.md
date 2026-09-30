# Execution and audit SQLite storage

Both remediation_execution.py and remediation_audit.py resolve
remediation_actions.db through storage_paths.database_path at call time.
With DGS_DATA_DIR configured, both tables live in that directory. An unset
or blank setting retains working-directory storage. Explicit DB_NAME
overrides remain supported; execution and audit overrides must identify
the same file when records are intended to share a database.

The directory must already exist and be writable by the runtime user.
A missing or inaccessible configured directory raises a database error;
there is no fallback to a second database in the working directory.
Runtime initialization does not move or merge historical databases.

## Existing installation cutover

1. Stop application processes, workers, CLI scripts, and other writers,
   including remediation execution. Record the actual resolved source and
   destination paths, including explicit overrides. Do not run initialization
   against an unknown production database merely to inspect it.
2. Inspect the source read-only. Verify its schema, PRAGMA integrity_check,
   action and audit counts, action IDs, account/provider bindings, approval
   and execution statuses, evidence authentication fields, and audit ordering.
   Do not export secrets or sensitive row values into operational logs.
3. Take a SQLite-consistent backup using the SQLite backup API or an approved
   backup command. Do not copy only the main file while WAL writers are active.
   Preserve the original and securely retain the current and previous evidence
   HMAC keys needed to verify historical records. Keys are not stored in this
   database.
4. Rehearse restoring the backup into an empty temporary location. Check schema,
   integrity, both tables, IDs, record counts, and signing evidence. Evidence
   verification requires the matching configured key; it appends a verification
   audit event, so run rehearsal on the restored copy and account for that event.
   Never execute live remediation as a storage validation step.
5. Refuse an existing destination database; investigate separately rather than
   overwriting or merging records. Restore the verified backup to
   DGS_DATA_DIR/remediation_actions.db. Give the runtime user appropriate
   ownership and directory write access for SQLite journal/WAL files.
6. Start with the new configuration. Confirm both modules resolve to the same
   destination and historical records remain available. Inspect integrity,
   approvals, outcomes, and evidence before resuming remediation writers.
   Retain the verified original until cutover acceptance.

Changing DGS_DATA_DIR before relocation can initialize an empty destination
and make historical actions and audit events appear absent. It does not
delete the original; stop writers and resolve the discrepancy before continuing.

## Backup and rollback

The default backup inventory does not yet include remediation_actions.db.
Include the resolved file explicitly in complete backups, along with the
other stores in the [database inventory](../architecture/DATABASE-INVENTORY.md).
Protect backups and evidence keys separately, and rehearse complete restoration.

Before rollback, stop writers and back up the current destination consistently.
If writes occurred after cutover, preserve and reconcile those changes through
a reviewed recovery process; pointing at an old source would discard them from
the active view. Restore a verified current copy to the intended location,
verify evidence and audit relationships, and then change configuration and
restart. Do not automatically merge independently modified databases.

## Validation coverage

Regression tests exercise configured and working-directory defaults, explicit
overrides, missing-directory failures, call-time resolution without automatic
relocation, and a SQLite backup preserving all action/audit rows and valid HMAC
evidence across repeated initialization. Cloud execution is mocked in the
signed-evidence test. CI also creates a pending action and its audit event in
the hardened non-root, read-only container and checks persistence under /data.
These checks validate application behavior, not an unseen deployment's data
or cutover. Schema-version adoption remains separate work.
