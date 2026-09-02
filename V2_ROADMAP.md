# DGS Sentinel AI v2 Enterprise Operations Roadmap

**Roadmap status:** Active
**Current phase:** Phase 1 Stabilization
**Baseline:** `main` commit `9a35b3e`
**Last verified:** September 2, 2026

## Objective

Advance DGS Sentinel AI from its production-oriented engineering foundation into a supportable, multi-tenant cloud-security platform with verified security, data protection, deployment, recovery, and operational controls.

DGS Sentinel AI is not currently represented as deployed at production scale across multiple paying customers.

## Status Definitions

| Status | Meaning |
| --- | --- |
| Implemented | Capability exists and has supporting verification |
| Partial | A useful foundation exists, but the workstream is incomplete |
| Planned | Approved direction without complete implementation |
| Blocked | Cannot proceed until a dependency or control is resolved |

## Current Phase Summary

| Workstream | Status |
| --- | --- |
| Gate 0 repository and release governance | Implemented |
| Multi-tenant security | Implemented |
| Persistent authentication | Implemented |
| Tenant authorization | Implemented |
| User administration | Implemented |
| Tenant-scoped dashboards | Implemented |
| Tenant-aware AI engineering | Implemented foundation |
| Documentation and workspace standards | In progress |
| Whole-production-code coverage | Partial |
| Complete database backup and recovery | Partial |
| Formal schema migrations | Planned |
| Scheduled cloud scanning | Planned |
| Enterprise alert routing | Partial |
| Centralized audit and compliance | Partial |
| Infrastructure as code | Planned |
| Controlled staging deployment | Planned |
| Controlled customer pilot | Planned |

## Gate 0 - Repository and Governance

**Status:** Implemented

Completed controls:

- Verified repository, branch, commit, and working-tree state.
- Reconciled the v2 development history.
- Verified 447 passing tests.
- Verified Bandit, pip-audit, pip check, and secret scanning.
- Verified 122 tracked Python files as syntax-valid during local validation.
- Enabled CI for v2 and phase branches.
- Merged pull request #23 into `main`.
- Protected `main`.
- Required pull requests.
- Required Python 3.11, Python 3.13, Security Scanning, and Hardened Docker Image checks.
- Blocked force pushes and deletion of `main`.
- Enabled GitHub Private Vulnerability Reporting.
- Verified post-merge CI on `main`.

## Phase 1 - Stabilization

**Status:** In progress

### 1. Professional Documentation

**Status:** In progress

Completed:

- Phase 1 Stabilization Audit.
- Current-State Architecture.
- Security policy.
- Coordinated vulnerability disclosure.
- Engineering contribution standards.
- Verified release changelog.

Remaining:

- Consolidate and correct the root README.
- Add production deployment and rollback runbook.
- Add database and migration architecture decision record.
- Add release procedure.
- Add incident-response and recovery runbooks.
- Add AI security and governance documentation.

### 2. Multi-Tenant Security Assurance

**Status:** Implemented, with continuing release-critical verification

Completed:

- Stable tenant keys.
- Tenant-scoped client access.
- Tenant-scoped assets and scan results.
- Tenant-scoped remediation records.
- Tenant-scoped operational monitoring.
- Tenant-scoped executive dashboard.
- Tenant-scoped SOC dashboard.
- Tenant-scoped asset dashboard.
- Tenant-scoped AI context.
- Tenant-scoped AI assets.
- Negative authorization tests.

Remaining:

- Maintain tenant-isolation regression coverage for every new data path.
- Add end-to-end tenant-isolation tests for exports and major UI workflows.
- Include tenant impact in every relevant pull request.

### 3. Production Authentication

**Status:** Implemented foundation

Completed:

- Persistent users.
- Password hashing.
- Secure session management.
- Session expiration.
- Failed-login tracking.
- Account lockout.
- Authentication audit events.
- User activation and deactivation.
- Password reset.
- User administration.
- Client-access assignment.

Remaining:

- Document identity lifecycle operations.
- Review the eventual retirement of legacy authentication fallback.
- Define SSO and external identity-provider requirements.
- Add MFA strategy for production use.

### 4. Test and Coverage Hardening

**Status:** Partial

Verified baseline:

- 447 tests passed.
- 48 test modules.
- Python 3.11 and Python 3.13 CI.
- 40% whole-production-code coverage.
- Strong focused coverage for tenant and user-security modules.

Gaps:

- `app.py` has 0% measured coverage.
- The active AssumeRole scan engine has 0% measured coverage.
- Headless scanning, reporting, client-detection storage, and several ingest modules have 0% measured coverage.
- `sentinel_ai_analyst.py` has 19% measured coverage.
- CI coverage enforcement currently covers only selected modules.
- CI compilation covers only selected production modules.

Planned work:

- Compile all tracked production Python files in CI.
- Publish an honest whole-production-code coverage result.
- Prevent whole-code coverage regression.
- Add tests for critical active execution paths.
- Extract testable domain logic from the Streamlit application incrementally.

### 5. Persistence and Schema Management

**Status:** Partial

Current databases include:

- `assets.db`
- `clients.db`
- `remediation.db`
- `users.db`
- `ai_assets.db`
- CAASM alert persistence.
- Operational-monitoring persistence.

Current limitations:

- No formal migration framework.
- No centralized schema-version registry.
- Runtime table creation.
- Inline schema updates.
- Multiple independent SQLite files.

Planned work:

- Document current schemas.
- Create an architecture decision record for production persistence.
- Approve a formal migration strategy.
- Define PostgreSQL or another production datastore only after architecture review.
- Preserve tenant boundaries during migration.
- Add migration and rollback testing.

### 6. Backup and Recovery

**Status:** Partial

Completed:

- Backup and recovery tooling.
- Backup manifests.
- Integrity checks.
- Restoration tests for existing covered databases.
- Backup/recovery command-line tooling.

Current default coverage:

- `assets.db`
- `clients.db`
- `remediation.db`

Required additions:

- `users.db`
- `ai_assets.db`
- CAASM alert data.
- Operational-monitoring data.
- Other required audit and execution data.

Exit requirements:

- Complete backup inventory.
- Verified restoration for every required database.
- Recovery-time and recovery-point objectives.
- Documented retention and encryption.
- Recovery drill evidence.

### 7. Application Maintainability

**Status:** Partial

Verified concerns:

- `app.py` contains 9,619 lines.
- Much of the Streamlit page logic runs at module level.
- Broad exception handling exists across integration modules.
- Several older scan-engine files appear unreferenced.
- A duplicate nested application directory remains tracked.

Planned work:

- Map active and legacy modules.
- Remove only verified obsolete files through reviewed pull requests.
- Extract application services behind tests.
- Reduce broad exception handling at high-risk boundaries.
- Keep refactoring separate from new features.

## Phase 2 - Production Foundation

**Status:** Planned

### Deployment Architecture

Planned:

- Infrastructure as code.
- Environment-specific configuration.
- Approved secret management.
- Repeatable staging deployment.
- Controlled production deployment.
- Deployment verification.
- Rollback procedure.
- Image provenance and version strategy.
- Production database services.
- Encryption at rest and in transit.

### Operations and Observability

Planned:

- Centralized logs.
- Metrics and alerting.
- Defined service objectives.
- Incident-response runbook.
- Support and escalation process.
- Vulnerability-management process.
- Backup monitoring.
- Recovery drills.
- Capacity and cost monitoring.

### Scheduled Cloud Scanning

**Status:** Planned

Required capabilities:

- Recurring AWS scans.
- Recurring Azure scans.
- Scan history and outcomes.
- Overlap prevention.
- Retry and timeout controls.
- Tenant-safe scheduling.
- Failure alerting.
- Manual pause and cancellation.
- Audit evidence.

## Phase 3 - Controlled Pilot

**Status:** Planned

Pilot requirements:

- One approved design-partner tenant.
- Read-only assessment as the default.
- Explicit authorization for cloud access.
- Least-privilege AWS and Azure roles.
- Verified onboarding and offboarding.
- Measured scan completion.
- Finding-quality review.
- False-positive tracking.
- Report-usefulness feedback.
- Support boundaries.
- Pilot exit report.
- Go or no-go decision for broader beta.

Remediation should remain dry-run or explicitly approved during the pilot.

## Phase 4 - Capability Expansion

**Status:** Planned

Deferred until stabilization and pilot evidence are complete:

- Deeper Azure coverage.
- Expanded identity-exposure analytics.
- Compliance mapping.
- Evidence workflows.
- SOC dashboards.
- SIEM and XDR integrations.
- Scheduled scanning.
- Email alerting.
- Slack alerting.
- Microsoft Teams alerting.
- Generalized severity routing.
- Additional guarded remediation actions.

## Phase 5 - Commercial Readiness

**Status:** Planned

Required work:

- Verified capability matrix.
- Packaging and pricing.
- Licensing.
- Privacy terms.
- Customer security package.
- Support model.
- Onboarding documentation.
- Product demonstrations.
- Custom Sentinel marketing website.
- Accurate marketing claims.
- Commercial release checklist.

## Current Phase 1 Priorities

1. Complete canonical documentation.
2. Expand CI compilation to all tracked production modules.
3. Establish whole-production-code coverage in CI.
4. Test critical active execution paths.
5. Expand backup and recovery scope.
6. Document schemas and approve a migration strategy.
7. Review high-risk broad exception handling.
8. Remove verified legacy and duplicate files.
9. Add staging and deployment architecture.
10. Publish a stabilized v2.1 release candidate.

## Phase 1 Definition of Done

Phase 1 is complete when:

- Documentation accurately distinguishes implemented, partial, and planned capabilities.
- All tracked production Python files are syntax-validated in CI.
- Whole-production-code coverage is consistently measured.
- Critical active execution paths have targeted tests.
- Required databases are included in backup and restore verification.
- Current schemas are documented.
- A migration strategy is approved.
- High-risk broad exception handlers are reviewed.
- Obsolete tracked files are safely removed.
- Deployment and rollback procedures are documented.
- CI and security checks pass.
- The stabilized release candidate is reviewed through a protected pull request.
