# Scan findings storage

The legacy headless scanner's `db.py` now resolves `dgs_sentinel.db` through
the shared storage helper. With `DGS_DATA_DIR=/data`, initialization, saves,
and reads use `/data/dgs_sentinel.db`. Without that setting, the existing
working-directory location is retained. Explicit `db.DB_NAME` overrides
continue to take precedence for tests and deliberately configured callers.

The directory must exist and be writable. An unavailable configured directory
raises an error; storage does not silently fall back to the app directory.
The `scan_findings` schema and saved values are preserved. New scan timestamps
use explicit UTC offsets; historical timestamps are not rewritten.

## Existing data cutover

Files are not copied, merged, or deleted automatically. If historical findings
are stored outside the newly configured location, complete an explicit
relocation before resuming scans.

1. Stop the application, scheduled scans, and any other writers.
2. Identify the actual source and destination files. If both contain data,
   preserve both and reconcile them explicitly before proceeding.
3. Create a SQLite-consistent backup of the source, verify checksums and
   integrity, and rehearse restoration. Default backup scope includes
   DGS_DATA_DIR/dgs_sentinel.db; explicitly add a legacy or overridden source
   when its actual path is elsewhere.
4. Restore the verified backup into the prepared destination without
   overwriting an existing database. Do not copy a live SQLite file and
   discard its WAL or journal sidecars.
5. Confirm the schema, record count, IDs, and representative findings are
   preserved. Set ownership and permissions for the runtime user.
6. Start with the intended `DGS_DATA_DIR`, verify historical reads, then
   perform an authorized scan and confirm new records use that same file.

Keep the original file and verified backup until cutover is accepted.
For rollback, stop writers and preserve the destination state first.
Restore a verified compatible backup to the location used by the prior
release, accounting for findings written after cutover. Simply returning
to a stale legacy file can lose visibility of newer findings.

## Scope and verification

Seven regression tests cover configured reads and writes, repeated
initialization with existing rows, ID preservation, overrides, legacy
defaults, call-time resolution, no automatic relocation, unavailable
directories, and empty saves. CI saves and reads a synthetic finding inside
the non-root read-only container and verifies its database is under `/data`.

This change does not add tenant identifiers, a version registry, automatic
schema upgrades. Default backup scope now includes the resolved file. The
[database inventory](../architecture/DATABASE-INVENTORY.md) lists the
remaining path, schema, health, and recovery gaps.
