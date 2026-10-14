# Read-only deployment relationship and evidence checks

`validate-set` extends local checks across all nine SQLite domains. It never
initializes a database, repairs data, adopts a registry, executes a cloud action,
or writes an audit event. Adoption eligibility is false in every result.

## Input and consistency

Stop Sentinel, scans, and monitoring writers, or use a verified coherent backup
set. Run:

```bash
python -m scripts.database_migrations_cli validate-set --confirm-stopped --json
```

Defaults resolve through `DGS_DATA_DIR`. With path overrides, specify **all nine**
domains using repeated `--database filename=/absolute/path` arguments. Partial
scope, duplicate domains, aliased paths, missing files, and absent confirmation
cannot pass; missing files are never created.

Each file has a held read-only/query-only transaction, reused for local and
relationship checks, including committed WAL data. SQLite has **no atomic snapshot
across nine independent files**. Operator confirmation cannot prove stopped
writers or coherent provenance; use one stopped deployment or coherent backup.

Inspection limits are 30 seconds for the set, 100,000 application rows per domain,
512 characters per compared identifier, and 1,000,000 characters/bytes per selected
evidence field. Limits produce ERROR, not a corruption finding. Error results
discard partial reports and counts.

## Relationships

Tenant keys in assets, remediation items, health runs, access assignments, optional
authentication-audit keys, AI assets, and AI relationships are checked against
saved clients. Missing references are counted without exposing their values.

`__dgs_system__` is recognized only for internal health runs. Reserved client-catalog
keys require review. `__legacy_unassigned__` remains unresolved; no ownership is
substituted. AI endpoints are compared by both tenant and AI asset ID; missing
endpoints require review because current writers allow relationships before
inventory records are created.

Nonempty CAASM alerts, legacy scan findings, and execution-action stores require
ownership review because their schemas lack stable tenant keys. Client names and
cloud account IDs are not used to guess ownership.

## Evidence

The runtime signer and read-only checker share a pure payload builder, key-ID
derivation, and HMAC-SHA256 helper. The signed payload and runtime signature format
are unchanged. This command never calls the audit-writing runtime verifier.

Keys load lazily from existing environment/Streamlit configuration:
`DGS_REMEDIATION_EVIDENCE_HMAC_KEY` and
`DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS`. As in the runtime, a current key is
required to load previous keys. At most 32 keys of up to 4,096 characters are
accepted. Keys are not accepted as CLI arguments or printed. Missing keys do not
affect an empty store but cannot verify signed records. Do not replace keys merely
to suppress a result.

| Evidence count status | Meaning |
| --- | --- |
| VERIFIED | Supported HMAC matches the signed payload and a configured current/previous key |
| MISSING | Terminal live action lacks a signature |
| MALFORMED / UNSUPPORTED | Invalid/partial authentication metadata or unsupported format |
| KEY_UNAVAILABLE / KEY_MISMATCH | Configuration or matching key unavailable |
| TAMPERED | Signature differs from the current signed payload |
| NOT_REQUIRED_FOR_SIMULATION | Unsigned simulation; no live execution proved |
| NOT_RECORDED | No signature recorded for other nonterminal/legacy metadata |

Terminal live actions also require Approved metadata. This does not reconstruct
complete lifecycle/audit history or prove a cloud change. Existing signatures omit
cloud-provider, Azure identifiers, tenant ownership, and other context: VERIFIED
does **not** authenticate the whole record. These limitations appear in every
report; populated adoption remains disabled even when signatures match.

## Outcomes and privacy

| Deployment status | Exit | Meaning |
| --- | --- | --- |
| SET_CHECKS_PASSED | 0 | Implemented checks pass; adoption eligibility remains false |
| RELATIONSHIP_OR_EVIDENCE_ISSUES / BLOCKED / ERROR | 1 | Link/evidence issue, failing local prerequisite, or inspection/configuration failure |
| REVIEW_REQUIRED / INCOMPLETE | 2 | Unresolved ownership/inventory links or incomplete input/context |

JSON contains safe local reports, aggregate relationship counts, evidence counts,
and limitations. No action IDs, payloads, hashes, key IDs, keys, or audit contents
are included. Protect saved reports because paths/counts are operational metadata.

Legacy ownership, full signed cloud/tenant context, complete remediation lifecycle
validation, historical schemas, complete backup/restore evidence, and locked-target
revalidation remain gates before enabling populated adoption.
