# Read-only baseline schema recognition

The baseline command recognizes one reviewed fresh schema candidate for each
of the nine SQLite domains. Candidate ID fresh_09ce292 identifies the schema
definitions extracted from commit 09ce292. It is a recognition label, not an
adopted migration version or application readiness certification.

```bash
python -m scripts.database_migrations_cli baseline
python -m scripts.database_migrations_cli baseline --json
python -m scripts.database_migrations_cli baseline --database users.db=/path/to/users.db --json
```

Default scope follows DGS_DATA_DIR at call time. Explicit domain=path selections
replace defaults; repeat the option to inspect more than one domain. Each domain
must be a reviewed filename and may be specified only once. Module DB_NAME
overrides and legacy external copies are not discovered automatically.

## Reviewed definitions

database_migrations/baselines contains nine reviewed SQL definitions and a
manifest with exact definition-file SHA-256 checksums and schema fingerprints.
The runtime does not execute these SQL files. Tests create isolated fixtures from
them and compare each with the real current initializer. Treat released definitions
as immutable; review a new candidate rather than quietly redefining an old label.

Fingerprinting reads sqlite_master plus table_xinfo, index_list, index_xinfo,
and foreign_key_list. It covers tables, views, triggers, columns (including
generated/hidden columns), declared types, nullability, defaults, primary keys,
unique/index column order, direction, collations, partial/expression index SQL,
foreign-key actions, and full tokenized schema SQL for CHECK/trigger behavior.
Whitespace and keyword case outside quoted tokens are normalized; quoted tokens
are preserved. Application records and sqlite_sequence values are not read into
the fingerprint. SQLite-maintained schema objects are excluded, but internal
constraint indexes are captured through their owning table's index metadata.

The fresh candidates include tenant-key triggers omitted from the earlier
inventory's illustrative SQL blocks. Canonical reviewed files and integration
tests define recognition; a matching column list alone is insufficient.

## Outcomes

| Status | Meaning |
| --- | --- |
| RECOGNIZED | Fresh schema shape exactly matches its reviewed domain candidate. |
| UNKNOWN | Missing/changed/extra objects, legacy shape, or another schema combination. |
| REGISTRY_PRESENT | Registry table/view already exists; inspect status before planning adoption. |
| MISSING | File absent; no file or parent directory created. |
| INTEGRITY_FAILED | SQLite quick_check failed. |
| ERROR | Database unreadable/corrupt, read limit exceeded, or reviewed definition invalid. |

Exit 0 means every selected schema was RECOGNIZED. Exit 2 reports missing,
unknown, or registry-present state. Exit 1 reports inspection/integrity errors.
JSON exposes safe domain/path/status metadata, a schema fingerprint, and the
reviewed label; it does not print schema SQL, stored row values, or exception text.

## Boundaries and deployment use

The command uses the same mode=ro, query_only, trusted_schema, snapshot, bounded
read, and connection cleanup behavior as migration status. It imports no runtime
initializer and does not create tables, repair indexes, backfill tenant keys,
insert registry rows, or apply a migration. SQLite WAL coordination may use
sidecars; immutable mode is avoided so committed WAL state remains visible.

Only current fresh shapes are reviewed. Historical inline ALTER/rebuild variants,
quoting differences, SQLite metadata differences, or legitimate custom indexes may
produce UNKNOWN even when they appear functionally equivalent. Stop and review
those schemas; do not run initialization merely to obtain a recognized result.
No ambiguous or unknown combination is automatically accepted.

RECOGNIZED does not validate tenant ownership, orphaned relationships, password
hashes, account lockouts, execution approvals, audit chronology, HMAC evidence,
or complete backup scope. Matching schema can contain invalid application data.
Status still reports UNVERSIONED until controlled adoption is implemented.
Before adoption, require verified complete backups, restore rehearsal, data
invariant checks, exclusive access, and approved operational evidence under
ADR-0001. Adoption, migration apply, and startup enforcement remain pending.
