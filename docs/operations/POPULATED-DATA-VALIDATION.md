# Read-only populated data validation

`validate-data` inspects each selected SQLite database in one bounded read-only
snapshot. It never imports a database initializer, creates a missing file,
modifies records, creates registry entries, or enables populated adoption.

It accepts the exact reviewed fresh schema shapes in all nine domains. A file
with an existing registry must also have the exact reviewed version-one registry
contract and matching history/checksum. Historical schema variants remain refused
until separately reviewed; do not initialize or repair a file to force a match.

## Usage

```bash
python -m scripts.database_migrations_cli validate-data --json
```

The default scope is the nine default paths from `DGS_DATA_DIR` (or the current
working directory when unset). For installations with path overrides, explicitly
identify each actual file; an omitted override is not automatically discovered:

```bash
python -m scripts.database_migrations_cli validate-data \
  --database users.db=/absolute/data/users.db \
  --database clients.db=/absolute/data/clients.db \
  --database assets.db=/absolute/data/assets.db \
  --json
```

The command can read active WAL databases and includes committed WAL data. It
uses read-only/query-only connections with bounded SQL execution. Each file is
an independent snapshot, not a deployment-wide transaction. Inspect a stopped
deployment or coherent backup set before making any upgrade decision.

## Implemented local checks

| Scope | Checks |
| --- | --- |
| Every domain | SQLite integrity, exact schema, declared foreign-key references, table row counts |
| Reviewed identifiers | Required tenant/account/asset identifiers are nonblank strings without leading/trailing whitespace; optional authentication tenant keys are normalized when present |
| Numeric fields | Present risk scores and counters are nonnegative integers; supported flags are integer 0 or 1 |
| User accounts | Supported role, global-admin role consistency, username length, encoded PBKDF2 hash structure/iteration limits, UTC account timestamps |
| User access and authentication events | Declared user references, UTC grant/event timestamps, object-shaped audit JSON within a 1,000,000-character parsing limit |
| Remediation action audit | Present action references point to an existing action in the same file |

Identifier policies are explicitly listed in the implementation and follow the
current writers. Free-text fields are not treated as identifiers. For example,
blank CAASM alert messages and nullable legacy scan-findings fields remain
supported. Risk scores are not given an invented upper limit. Password hashes
are checked for supported metadata shape, not tested against passwords.

## Output and exit codes

JSON includes only the domain, path, result, counts, fixed check codes, reviewed
table/column names, limitations, and `adoption_eligible: false`. It does not include
usernames, tenant values, assets, findings, audit contents, passwords, password
hashes, or raw exception text. Protect reports because paths and aggregate counts
can still reveal operational metadata. Text output prints a summary; use JSON to
inspect the individual violation counts.

| Result | Meaning | Exit |
| --- | --- | --- |
| LOCAL_CHECKS_PASSED | All implemented checks completed without violations; eligibility remains false | 0 when every target passes |
| DATA_ISSUES | One or more local policies found violations; no repair occurred | 1 |
| INTEGRITY_FAILED / INVALID_REGISTRY / ERROR | Integrity, reviewed history, I/O, or bounded-read failure | 1 |
| MISSING / UNKNOWN_SCHEMA | Target absent or not in the reviewed schema scope; checks incomplete | 2 |

Error/timeout results discard partial counts and check results. Unknown-schema
files receive no data checks and expose no unknown table names. SQL may fail
earlier on an integrity violation than the more specific semantic check.

## Remaining gates

`LOCAL_CHECKS_PASSED` is deliberately narrower than migration readiness. It does
not establish cross-database tenant references, undeclared relationships such as
AI relationship endpoints, remediation evidence authenticity, remediation state
transitions, cloud credential validity, deployment compatibility, or historical
schema support. Large databases may exceed the bounded execution limit; a timeout
must not be treated as a pass.

Populated adoption stays disabled. Before enabling it, define and review those
remaining policies, validate one coherent deployment snapshot, verify complete
backup/restore evidence, and revalidate the locked target during adoption. Do not
delete data or manually insert registry rows to avoid a reported issue.
