# Controlled adoption of empty fresh schemas

This command establishes version 1 for **one existing, empty database** whose
schema exactly matches its immutable `fresh_09ce292` definition. It does not
execute the definition SQL, migrate application records, repair schema drift,
initialize missing files, or certify deployment readiness.

Populated databases are refused. In particular, an installation with user
accounts, authentication events, saved findings, clients, or remediation evidence
must wait for domain-specific data validation. Do not delete records to make an
installation eligible. Existing registries, including empty registries, are also
refused and require separate history inspection.

## Operator procedure

1. Stop Sentinel and all writers, background scans, and monitoring jobs.
2. Confirm the intended database path and environment. Read-only `baseline`
   recognition remains available; recognition alone does not authorize adoption.
3. Choose a **new backup filename** in an existing protected directory with
   sufficient free space for a complete SQLite snapshot and registry write.
4. Run the explicit command on an eligible empty test or fresh deployment file:

```bash
python -m scripts.database_migrations_cli adopt-empty \
  --database assets.db=/absolute/data/assets.db \
  --backup-path /absolute/backups/assets-before-baseline.db \
  --environment staging \
  --application-version YOUR_RELEASE_ID \
  --confirm-empty \
  --confirm-stopped \
  --json
```

`YOUR_RELEASE_ID` must identify the actual deployed release or commit. This is
an example, not an instruction to modify an existing populated installation.
The environment and release accept simple labels of at most 80 characters.

5. Save the JSON result in protected release evidence. It contains the domain,
   source and backup paths, environment, release, outcome, and, on success,
   baseline identity, exact definition checksum, version, and UTC timestamp.
   It contains no application values or credentials.
6. Run read-only `status` with the same explicit path. `CURRENT` means the
   registry matches this release's catalog; it does not certify schema/data
   compatibility or startup readiness. Review each file independently.

## Guarantees and failure behavior

- No default target scope for adoption: exactly one explicit database is required.
- Both confirmations, environment, release, and a backup filename are required.
- A bounded SQLite write reservation excludes other SQLite writers while the
  original schema and emptiness are checked, backed up, and adopted.
- Backup uses SQLite's snapshot API, including committed WAL state. It is created
  exclusively with mode 0600, verified for integrity/schema/emptiness, and flushed
  before any registry write. Existing backups and database sidecar paths are refused.
- A single transaction creates the registry and inserts version 1. Post-write
  checks verify application schema shape, emptiness, and registry identity before
  committing. Adoption changes only the registry; ordinary startup never adopts.
- A verification or insertion failure rolls back the registry. A completed,
  verified backup remains available even if a later step fails; an incomplete or
  invalid backup created by this operation is removed.
- Errors use fixed messages and do not print SQLite error text or stored values.
  Review local storage, permissions, locks, and capacity when `ERROR` is reported.
- Exit code 0 means this one file was adopted; any refusal/error returns 1.
  Repeat adoption refuses the existing registry without making another backup.

## Recovery and remaining work

The backup is the entire **pre-adoption**, unversioned SQLite snapshot. Before
recovery, stop every writer and preserve the failed state and evidence. Restore
to a new path first, verify integrity and read-only baseline recognition, and
complete the normal reviewed recovery procedure; do not copy over a live SQLite
file or leave stale WAL/SHM files attached to a replacement database.

Tests exercise restoration into a new file for all nine domains, rollback,
populated-file refusal, WAL state, exclusive writers, and backup preservation.
There is no nine-file atomic transaction or whole-deployment recovery guarantee.
Populated/historical baseline adoption, ordered upgrade application, compatibility
enforcement at startup, and replacement of inline runtime schema upgrades remain
separate implementation phases.
