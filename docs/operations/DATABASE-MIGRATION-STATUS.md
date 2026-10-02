# Read-only SQLite migration status

This first migration-framework step defines the per-database registry contract,
immutable migration descriptors, exact-payload checksums, and a status inspector.
It does not adopt baselines, apply SQL, initialize registries, replace runtime
initializers, enforce startup compatibility, or add migration locking.

## Commands

Inspect all nine default SQLite paths resolved through DGS_DATA_DIR:

```bash
python -m scripts.database_migrations_cli status
python -m scripts.database_migrations_cli status --json
```

For deliberately overridden or legacy paths, select a reviewed domain explicitly:

```bash
python -m scripts.database_migrations_cli status --database users.db=/path/to/users.db --json
```

Repeat --database for multiple domains. These selections replace default scope.
Each domain must be one of the nine filenames in storage_paths.SQLITE_DATABASE_NAMES
and may appear only once. Do not infer that module DB_NAME overrides are discovered.

## Registry contract and catalog

database_migrations.REGISTRY_SCHEMA defines schema_migrations in each existing
database, with version, name, checksum, applied_at, and application_version.
Versions start at one and must be contiguous; names are stable lowercase identifiers
and unique per domain; checksums are SHA-256 of exact UTF-8 migration SQL, including
whitespace; timestamps must contain an explicit UTC offset. Applied SQL must remain
immutable after release. This module never executes descriptor SQL.

No domain currently has an approved migration or baseline: get_migrations returns
an empty tuple for all nine domains. Existing files without a registry are
UNVERSIONED; they are not recognized or adopted by status. A populated registry
is UNSUPPORTED_VERSION with the current empty catalogs. Do not manually insert
registry rows to suppress these results. Adoption must later validate deployed
schemas/data invariants and verified backup/restore evidence.

## Results and exit codes

| Status | Meaning |
| --- | --- |
| MISSING | No database exists; no file or parent directory was created. |
| UNVERSIONED | Registry absent; baseline recognition/adoption is required. |
| EMPTY_REGISTRY | Empty registry does not prove a baseline was adopted. |
| INVALID_REGISTRY | Object shape, uniqueness, history ordering, or metadata invalid. |
| UNSUPPORTED_VERSION | History includes a version not in the reviewed release catalog. |
| HISTORY_MISMATCH | Applied identity differs from the reviewed migration name. |
| CHECKSUM_MISMATCH | Applied checksum differs from the exact reviewed SQL payload. |
| PENDING | Reviewed catalog has unapplied migrations; no changes performed. |
| CURRENT | Registry metadata matches a supplied catalog; schema/data compatibility unproved. |
| INTEGRITY_FAILED | SQLite quick_check reported integrity failure. |
| ERROR | Unreadable/corrupt database, invalid path type, or bounded read failure. |

Exit 0 requires every inspected registry to be CURRENT. Exit 2 means missing,
unversioned, empty, or pending state; invalid arguments also use argparse exit 2.
Exit 1 means an inspection or registry failure. Because catalogs are currently
empty, the shipped CLI cannot report CURRENT or certify startup readiness.
JSON exposes paths and safe status/count/version metadata, not persisted migration
names, release strings, timestamps, application rows, or underlying exception text.

## Read-only behavior and limitations

Status imports no application database initializer. It opens existing databases
using an escaped file URI with mode=ro, enables connection-local query_only and
disables trusted_schema, then reads within a transaction. Connections close on
success and error. SQLite lock timeout is three seconds; a progress handler bounds
SQL execution to approximately five seconds per database. Databases are inspected
sequentially, without a global snapshot across files.

The inspector does not write schema, registry rows, or application data and does
not create missing databases. Standard SQLite WAL coordination may require existing
sidecars or directory access; sidecar coordination is not a schema/data migration.
It deliberately does not use immutable mode, which could hide committed WAL data.
Inspect with writers stopped when a stable cross-database observation is required.

Registry-shape checks cover columns, types, nullability, primary key, and unique
migration names. They do not certify every CHECK constraint, trigger, application
table, index, foreign key, tenant boundary, authentication state, or signing
evidence. Even a matching fixture catalog's CURRENT result only validates migration
metadata. Plan/apply/adopt/verify commands, schema recognition, startup compatibility,
locking, and recovery execution remain future work under ADR-0001.
