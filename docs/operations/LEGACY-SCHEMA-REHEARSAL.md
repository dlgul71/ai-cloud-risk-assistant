# Legacy schema rehearsal

This command creates three new test database files from the exact legacy schema
definitions in `database_migrations/legacy_schemas`. It never updates live or
source files, adopts a migration registry, assigns recovered ownership, verifies
signatures, or executes cloud actions. It is not a production migration command.

Stop all writers or use a coherent restored backup set. Choose a new output
directory under an existing parent, separate from the source directory:

```bash
python -m scripts.legacy_schema_rehearsal_cli \
  --source-directory "$HOME/sentinel-migration-rehearsal" \
  --output-directory "$HOME/sentinel-schema-rehearsal-v1" \
  --confirm-stopped
```

Only `remediation.db`, `operational_monitoring.db`, and
`remediation_actions.db` are converted. Other stores are out of scope. Missing AI
or CAASM stores are not created to make a deployment appear complete.

Before creating output, every source must match its entire reviewed legacy schema
fingerprint, pass integrity and foreign-key checks, and fall within the inspection
limits. Extra objects, missing guards, registries, linked files, and unfamiliar
schemas are refused. Operator confirmation is an assertion, not proof of coherent
provenance. Read-only source transactions include committed WAL state.

Each output uses the existing checksum-verified fresh definition. Copies use
explicit named columns. Every original row value, ID, audit entry, null provider,
and evidence field is compared against its source before commit. SQLite sequence
counters are preserved, including counters beyond the largest remaining ID.
Foreign keys, integrity, and the complete output schema are checked.

The old health schema has no tenant field. New health tenant fields receive
`__legacy_unassigned__`, explicitly recording unresolved ownership. No client or
system owner is inferred. Existing remediation legacy keys remain unchanged.
The new provider default applies to future inserts; old null values stay null.

A successful command writes `rehearsal.json` with row counts and limitations. The
new directory uses mode 0700; database files and the report use mode 0600. Reports
contain no application row values, hashes, signature key identifiers, or secrets.
Sources are unchanged on failure. Any failed output is incomplete, is retained for
local investigation, has no success report, and must never be deployed.

Limits: 100,000 rows per table, 1,000,000 characters/bytes per field and 50 MB of
aggregate SQLite field bytes per domain, in addition to source read deadlines.
Rehearsal output may still fail data/relationship checks and always remains
ineligible for adoption. Unassigned tenants, unavailable signing keys, missing
stores, and provider gaps remain review items.

## Check the converted copies

From the review checkout, run the existing read-only data validator on exactly the
three generated files:

```bash
python -m scripts.database_migrations_cli validate-data \
  --database "remediation.db=$HOME/sentinel-schema-rehearsal-v1/remediation.db" \
  --database "operational_monitoring.db=$HOME/sentinel-schema-rehearsal-v1/operational_monitoring.db" \
  --database "remediation_actions.db=$HOME/sentinel-schema-rehearsal-v1/remediation_actions.db"
```

LOCAL_CHECKS_PASSED applies only to the selected local checks. The preserved
legacy-unassigned ownership and unavailable original signing keys still require
review, even if all three local checks pass. Do not replace application databases
with rehearsal output.
