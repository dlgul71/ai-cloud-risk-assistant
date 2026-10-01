# SQLite backup and health coverage

Backup and health defaults share storage_paths.SQLITE_DATABASE_NAMES:
assets.db, clients.db, remediation.db, operational_monitoring.db, users.db,
ai_assets.db, caasm_alerts.db, dgs_sentinel.db, and remediation_actions.db.
Paths resolve under DGS_DATA_DIR at call time; unset/blank settings retain
working-directory behavior. Inventory resolution creates no databases.

Explicit create_backup(database_files=...) lists and CLI --database options
replace the default scope. health_checks.DATABASE_FILES overrides also replace
the default list. Runtime module DB_NAME overrides are not automatically
discovered by backup or health checks; provide those actual paths explicitly.
Existing packages remain readable with the unchanged manifest format.

## Missing files and status

Stores may be absent before the related feature has been initialized.
Missing files are reported as WARN by health checks, skipped by backup, and
listed in the manifest's missing_databases. Backup creation returns WARN
and the CLI exits with 2. Neither operation initializes missing databases.

Operators must decide whether a missing file is expected for their deployment
or evidence of incomplete recovery scope. Existing corrupt/unreadable files
fail health checks; backup errors are not converted to optional-file warnings.
Health checks close SQLite connections even when integrity checking fails.

verify_backup validates checksums and SQLite quick_check for packaged files.
It can return PASS for a package whose creation reported missing files.
Restore similarly restores packaged files only, and refuses existing destination
files. An empty package fails verification and cannot be restored. Review
missing_databases and verify actual deployment scope before accepting a backup.

## Backup and restore rehearsal

Stop writers when a consistent point across multiple databases is required.
The SQLite backup API captures committed WAL data for each file, but the nine
files are backed up sequentially rather than in one global transaction.

Create the default package:

```bash
python -m scripts.backup_recovery_cli create
```

Use the reported package path to verify and restore into an empty rehearsal
location:

```bash
python -m scripts.backup_recovery_cli verify /path/to/backup-package
python -m scripts.backup_recovery_cli restore /path/to/backup-package --restore-root /path/to/empty-rehearsal
```

For a legacy/overridden source, repeat --database for every intended file.
That option replaces defaults, so supply the complete required scope.

After restoration, verify schemas, record counts, tenant bindings, authentication
state, execution approvals/outcomes, audit relationships, and evidence integrity.
Historical signing evidence requires securely retained matching HMAC keys.
Do not execute live remediation as a restore test. Protect backups because
they include authentication and client data; store signing keys separately.

Snapshots, scan-result files, configuration, logs, and signing keys remain
outside this SQLite inventory. Schema-version adoption remains separate work.
See the [database inventory](../architecture/DATABASE-INVENTORY.md) for scope.

## Regression coverage

Tests cover shared call-time defaults, nine-file verified restore with unchanged
schemas, records, composite tenant IDs, binary payloads and audit history;
missing-file warnings without initialization; empty-package refusal; corruption
in each of the five newly included stores; committed WAL recovery; and default
versus explicit CLI scope. These are isolated temporary test databases and do
not certify the completeness of an unseen production deployment.
