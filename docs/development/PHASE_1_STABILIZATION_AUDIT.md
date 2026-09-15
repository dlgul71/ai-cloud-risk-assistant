# DGS Sentinel AI Phase 1 Stabilization Audit

**Audit date:** September 2, 2026
**Resolution update:** September 13, 2026
**Repository:** `dlgul71/ai-cloud-risk-assistant`
**Branch:** `phase-1-stabilization-docs`
**Baseline commit:** `9a35b3e`
**Status:** Read-only technical assessment completed
**Application-code changes:** None

## Executive Summary

DGS Sentinel AI has completed Gate 0 and entered Phase 1 stabilization. The verified platform includes multi-tenant security, persistent authentication, tenant authorization, tenant-scoped dashboards, user administration, AI-security capabilities, AWS multi-account assessment, Azure integrations, reporting, audit evidence, and guarded remediation.

The platform has a strong automated-test and security-scanning foundation. At the audit baseline, production-code coverage was uneven, persistence relied on multiple SQLite databases without formal migrations, backup scope was incomplete, the Streamlit application was highly concentrated in `app.py`, and product documentation did not fully reflect the implemented state. The documentation finding has since been addressed on the stabilization branch; the engineering limitations remain active.

DGS Sentinel AI remains accurately described as a DGS-developed, production-oriented, multi-client security platform. It is not currently represented as deployed at production scale across multiple paying customers.

## Gate 0 Closure

Gate 0 was completed before this audit.

- Pull request #23 merged the v2.0 and v2.1 work into `main`.
- Merge commit: `9a35b3e7cfe25f96ec992e0cc7e4d5d4414791ab`.
- `main` is protected.
- Pull requests are required.
- Required CI checks are enforced.
- Force pushes and branch deletion are blocked.
- Post-merge CI run `33456018907` passed.
- Python 3.11 passed.
- Python 3.13 passed.
- Security scanning passed.
- Hardened Docker image validation passed.
- The reviewed secrets baseline was reconciled.
- Local and remote `main` were synchronized with a clean working tree.

## Repository Inventory

- 153 tracked files.
- 122 tracked Python files.
- 48 test modules.
- 44,008 lines of tracked Python.
- No tracked SQLite database files.
- No `TODO`, `FIXME`, `HACK`, or `XXX` markers were found.
- No Terraform, deployment-infrastructure directory, or Compose configuration was found.
- Nine operational and administrative scripts are tracked.

## Test and Quality Baseline

### Verified Test Results

- 447 tests passed in 12.43 seconds during the Phase 1 local coverage run.
- Prior Gate 0 local validation also recorded 447 passing tests.
- CI runs tests on Python 3.11 and Python 3.13.
- CI runs `pip check`, Bandit, pip-audit, detect-secrets, Docker build validation, container hardening validation, and a Streamlit health check.

### Coverage Finding

At the audit baseline, the CI coverage threshold measured only:

- `app_config`
- `app_logging`
- `health_checks`

The Phase 1 whole-production-code assessment measured:

- 7,435 executable production statements.
- 4,492 missed statements.
- 40% total production-code coverage.

The historical selected-module CI coverage figure must not be described as whole-platform coverage.

Update, September 14, 2026: CI measurement now explicitly includes all 74 tracked non-test Python files, including scripts and the nested application. Run 34795081732 measured 7,648 statements and 4,543 missed statements (40.60%) on both Python 3.11 and Python 3.13; both versions passed 447 tests and recorded 82.91% combined focused coverage. That run failed only because secret-baseline line metadata needed updating. After the metadata update and addition of a 40.60% whole-production floor, run 34795463324 passed. The combined 70% focused gate remains intact, and Python 3.13 uploads the whole-production XML report. The earlier statement counts above are historical and use a different inventory; this update does not establish a test-coverage improvement.

Update, September 15, 2026: CI run 34928091875 passed on commit 6b6d98c. Both Python versions passed 456 tests and measured 43.03% whole-production coverage (7,648 statements; 4,357 missed), 38.36% AssumeRole engine coverage, and 82.91% combined focused coverage. Nine new mocked tests cover tenant-key validation, failed identity handling, partial EC2 regional failure, IAM/S3 unknown states, and tenant propagation to storage calls. The follow-up workflow change raises the whole-production floor to 43.03%; that threshold change requires its own CI verification. These tests do not establish downstream tenant isolation or exercise live AWS access.

### Major Coverage Gaps at the Original Audit Baseline

- `app.py`: 0%
- `scan_engine_phase3_assumerole.py`: 0%
- `scan_engine.py`: 0%
- `headless_scan.py`: 0%
- `client_analyst_report.py`: 0%
- `client_detection_store.py`: 0%
- Multiple AWS ingest modules: 0%
- `sentinel_ai_analyst.py`: 19%
- `demo_mode.py`: 31%

Newer tenant and identity components have substantially stronger focused coverage:

- `tenant_authorization.py`: 100%
- `storage_paths.py`: 100%
- `user_administration.py`: 97%
- `user_authentication.py`: 97%
- `user_db.py`: 92%

## CI Findings

### Strengths

- Python 3.11 and 3.13 validation.
- Dependency integrity checking.
- Bandit static analysis.
- Dependency vulnerability auditing.
- Committed-secret scanning.
- Non-root container execution.
- Read-only container filesystem testing.
- Dropped Linux capabilities.
- `no-new-privileges` enforcement.
- Persistent `/data` volume.
- Streamlit health-endpoint validation.

### Gaps

- At the audit baseline, compilation covered only 17 named production modules. This gap was resolved by compiling all 74 tracked non-test Python files in both supported CI versions.
- The audit-baseline coverage-enforcement gap was resolved with the 40.60% whole-production floor. The September 15 follow-up raises that floor to 43.03%, retaining the combined 70% focused gate. Critical execution-path coverage remains incomplete.
- GitHub Actions reports Node.js 20 deprecation warnings for action dependencies.
- The Python base image is version-tagged but not digest-pinned.
- There is no infrastructure-as-code deployment validation.

## Persistence Architecture

SQLite is used across multiple platform domains.

### Primary Databases

- `assets.db`
- `clients.db`
- `remediation.db`
- `users.db`
- `ai_assets.db`

Additional SQLite persistence supports:

- CAASM alerts.
- Operational monitoring.
- Remediation audit and execution records.

### Schema Management

- No Alembic or formal migration directory exists.
- Tables are created at application runtime.
- Schema evolution uses inline `ALTER TABLE` logic.
- No centralized schema-version registry was found.
- `caasm_alert_db.py` uses a relative `caasm_alerts.db` path instead of `DGS_DATA_DIR`.
- The relative CAASM alert path may be unwritable in the hardened read-only container.

### Backup and Recovery Gap

The current default backup set includes:

- `assets.db`
- `clients.db`
- `remediation.db`
- `operational_monitoring.db`

The default backup set does not include at least:

- `users.db`
- `ai_assets.db`
- CAASM alert persistence.

This is a high-priority recovery and tenant-continuity gap.

## Architecture and Maintainability

### Application Concentration

- `app.py` contains 9,619 lines.
- It contains 2,595 executable statements.
- It defines only 30 top-level functions.
- Most Streamlit page logic executes at module level.
- The module has no classes.
- This structure makes isolated testing and incremental maintenance difficult.

### Other Large Active Modules

- `sentinel_ai_analyst.py`: 1,801 lines.
- `scan_engine_phase3_assumerole.py`: 1,487 lines.
- `remediation_execution.py`: 1,163 lines.
- `user_db.py`: 1,158 lines.

### Exception Handling

Ninety-six broad `except Exception` handlers were found across 22 production modules. Some provide resilience around optional integrations, but broad handling can conceal import, configuration, network, and programming failures.

### Legacy and Duplicate Content

The following older scan engines appear unreferenced:

- `scan_engine_phase1_working.py`
- `scan_engine_phase2_3_working.py`
- `scan_engine_phase2_4_stable.py`

A nested `ai-cloud-risk-assistant/` directory contains:

- An empty README.
- An outdated unpinned requirements file.
- A second application file.
- A nested `.gitignore`.

These items require a reviewed cleanup decision before removal.

Ignored local backup files also exist in the working directory. They are not committed repository content and must not be deleted without a separate recoverability review.

## Documentation Findings

Existing documentation includes:

- Root README.
- V2 roadmap.
- CI workflow.
- Dockerfile.
- Environment example.
- Integration-validation documents.
- Backup/recovery and production smoke-test scripts.

At the audit baseline, missing canonical documentation included:

- `SECURITY.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`
- Architecture overview.
- Architecture decision records.
- Production deployment and rollback runbook.
- Release procedure.
- Incident-response and recovery runbook.
- Database migration strategy.
- AI security and governance model.

These documentation findings have been addressed on the stabilization branch. The root README was consolidated, corrected for the hardened runtime, and updated with persistent-data guidance. Documentation must continue to be maintained as engineering behavior changes.

## V2 Roadmap Status

| Workstream | Verified status |
| --- | --- |
| Multi-tenant security | Implemented and tested |
| Production authentication | Implemented; SSO remains planned |
| Scheduled cloud scanning | Not implemented |
| Enterprise alerting | Partial; Splunk HEC and CAASM alerting exist |
| Audit and compliance | Partial |
| Production operations | Partial |

Email, Slack, Microsoft Teams, generalized severity routing, formal recovery drills, full control mapping, production infrastructure, and production-scale operational validation remain incomplete or unverified.

## Stabilization Priorities

1. Maintain canonical documentation as engineering behavior changes.
2. Maintain the verified whole-production-code coverage baseline and raise the enforced floor as tests improve.
3. Add tests for active scanning, reporting, headless operation, and extracted application logic.
4. Expand backup and recovery coverage to all required databases.
5. Implement the accepted formal migration strategy.
6. Refactor `app.py` incrementally behind tests.
7. Replace broad exception handling with appropriately scoped failures.
8. Remove verified legacy and duplicate files through reviewed pull requests.
9. Add infrastructure-as-code and staging deployment controls.
10. Publish release notes and tag the stabilized v2.1 baseline.
11. Defer broad feature expansion until stabilization exit criteria pass.

## Phase 1 Exit Criteria

Phase 1 stabilization is complete when:

- Documentation accurately describes implemented, partial, and planned features.
- All tracked production Python files are syntax-validated in CI.
- Whole-production-code coverage is measured consistently.
- Critical active execution paths have targeted automated tests.
- All required databases are included in backup and restore verification.
- The current schema is documented and a migration strategy is approved.
- High-risk broad exception handlers are reviewed.
- Obsolete tracked files are safely removed.
- Production deployment and rollback procedures are documented.
- CI, security scans, Docker validation, and the full test suite pass.
