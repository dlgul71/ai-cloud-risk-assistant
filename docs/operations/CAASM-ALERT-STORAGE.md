# CAASM alert storage

CAASM alert persistence resolves `caasm_alerts.db` through the shared
`storage_paths.database_path` helper. With `DGS_DATA_DIR=/data`, every alert
operation uses `/data/caasm_alerts.db`. Without that environment variable,
the existing current-directory behavior is preserved. The configured
directory must already exist and be writable by the runtime user.

An explicit `caasm_alert_db.DB_NAME` override takes precedence, preserving
isolated tests and existing callers that deliberately set a database path.
The default path is resolved at call time.

## Existing installations

This change does not copy, merge, delete, or alter the schema of existing
databases. If a deployment previously wrote alerts in its working directory
while `DGS_DATA_DIR` pointed elsewhere, switching to the new code changes
which file is opened. Complete relocation before resuming application traffic
if the historical alerts must remain available.

1. Stop application processes and alert workers.
2. Identify the actual legacy file and the configured destination. If both
   locations contain databases, stop and reconcile them explicitly; do not
   overwrite either file.
3. Create and verify a SQLite-consistent backup of the legacy database.
   Include it explicitly in the backup scope: the current default backup
   inventory does not include CAASM alerts.
4. Restore the verified backup into the prepared destination without
   overwriting an existing database. Use the SQLite backup/recovery utilities,
   rather than copying a live database file that may have WAL sidecars.
5. Verify SQLite integrity and alert record counts. Confirm IDs, fingerprints,
   statuses, occurrence and notification counts, and audit timestamps are
   preserved. Set file ownership and permissions for the runtime user.
6. Start the application with the intended `DGS_DATA_DIR` and verify reads and
   writes use that location. Retain the original file and verified backup until
   the relocation is accepted.

For rollback, stop writers first and preserve the destination database,
including alerts written after cutover. Restore a verified compatible backup
to the location expected by the prior release. Do not merely point the old
release at a stale legacy file and assume post-cutover records are retained.

## Validation and scope

Unit tests cover the complete alert lifecycle under a configured directory,
legacy default behavior, explicit overrides, call-time path resolution,
preservation of the original file, and failure without fallback when the data
directory is unavailable. CI also initializes and reads alert storage inside
the non-root, read-only container with its writable `/data` volume.

This is the first storage prerequisite in ADR-0001. The migration registry,
baseline adoption, ordered schema migrations, expanded backup inventory, and
startup compatibility enforcement remain separate work. CAASM alert access
controls and schema are unchanged.
