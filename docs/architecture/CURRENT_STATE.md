# DGS Sentinel AI Current-State Architecture

**Document date:** September 2, 2026
**Architecture baseline:** `main` commit `9a35b3e`
**Document branch:** `phase-1-stabilization-docs`
**Status:** Verified current-state architecture
**Audience:** Engineering, security, operations, product, and future reviewers

## Purpose

This document describes the implemented architecture of DGS Sentinel AI as verified during the Phase 1 stabilization audit.

It separates implemented, partial, and planned capabilities. It is not evidence of production deployment across multiple paying customers.

## Product Position

DGS Sentinel AI is a DGS-developed, production-oriented, multi-client cloud-security platform.

The platform provides:

- Cloud assessment.
- Asset and identity visibility.
- Risk analytics.
- AI-assisted reporting.
- Role-based access control.
- Audit evidence.
- Guarded remediation.

Production-scale persistence, formal database migrations, infrastructure as code, centralized operations, and controlled pilot validation remain future work.

## Logical Flow

1. An Administrator, Analyst, or Viewer accesses the Streamlit application.
2. Authentication and session controls establish the user identity.
3. RBAC and tenant authorization determine permitted pages, clients, and actions.
4. Cloud discovery collects authorized AWS and Azure information.
5. Asset, finding, identity, and threat-intelligence data are correlated.
6. Risk scoring prioritizes exposures and findings.
7. Dashboards, AI analysis, CSV files, and PDF reports present results.
8. Remediation requires explicit authorization and approval.
9. Audit and execution evidence records consequential actions.

## Application Layer

### Primary Entry Point

`app.py` is the main Streamlit application entry point.

Current responsibilities include:

- Application startup and configuration.
- Authentication and session state.
- Navigation and page authorization.
- Tenant-aware data selection.
- AWS and Azure assessment workflows.
- Executive and operational dashboards.
- Client and user administration.
- AI-assisted analysis.
- PDF and CSV reporting.
- Remediation approval and execution views.
- Health and operational monitoring.
- Demo-mode output sanitization.

The module contains 9,619 lines and 2,595 executable statements. Much of the page logic runs at module level. This concentration is a major maintainability and testability concern.

### Supporting Services

Major supporting modules include:

- `sentinel_ai_analyst.py`
- `sentinel_ai_openai.py`
- `scan_engine_phase3_assumerole.py`
- `risk_engine.py`
- `asset_correlation.py`
- `client_analyst_report.py`
- `operational_monitoring.py`
- `health_checks.py`
- `user_administration.py`
- `remediation_execution.py`

## Identity and Access Architecture

### Authentication

The platform supports persistent user authentication backed by `users.db`.

Implemented controls include:

- Password hashing.
- Persistent user records.
- Active and locked account states.
- Failed-login tracking.
- Account lockout.
- Session expiration.
- Authentication audit events.
- Administrative password reset.
- User activation and deactivation.

Legacy environment-based authentication remains available only through an explicit option:

`DGS_ALLOW_LEGACY_AUTH_FALLBACK=false`

The fallback is disabled by default and should not be the standard production authentication path.

### Roles

Implemented roles are:

- Administrator
- Analyst
- Viewer

Permissions govern dashboard access, scan execution, client and user management, remediation approval and execution, evidence access, and health-information access.

### Tenant Authorization

Tenant authorization uses stable client keys and authenticated client assignments.

Implemented protections include:

- Tenant-scoped client access.
- Tenant-scoped assets and scan results.
- Tenant-scoped dashboards.
- Tenant-scoped remediation records.
- Tenant-scoped AI assets.
- Tenant-aware AI analysis.
- Global-administrator controls.

Tenant isolation is a release-critical boundary and must remain covered by negative authorization tests.

## AWS Architecture

Multi-account AWS assessment uses STS AssumeRole and client-specific account records.

Implemented capabilities include:

- Client account registration.
- Role-based connection testing.
- Account-aware findings.
- Multi-region assessment.
- Client-specific scan results.
- Headless scanning.
- Tenant-aware reporting.

Integrated AWS sources include IAM, EC2, S3, Security Hub, GuardDuty, AWS Organizations, AWS Config-related discovery, and STS AssumeRole.

Current use cases include MFA gaps, stale credentials, active access keys, public storage, cloud misconfiguration, vulnerability exposure, threat detections, and account-level risk summaries.

## Azure Architecture

Azure integration uses service-principal credentials and subscription-specific configuration.

Implemented foundations include:

- Subscription validation.
- Resource discovery.
- Compute discovery.
- Storage discovery.
- Storage-exposure analysis.
- Network-security-group analysis.
- Defender for Cloud intelligence.
- Azure remediation adapters.
- Azure resources in multicloud client accounts.

Azure coverage is less mature than AWS coverage and should not be described as full AWS parity.

## Threat and Vulnerability Intelligence

The platform correlates cloud and asset information with:

- CISA Known Exploited Vulnerabilities.
- National Vulnerability Database data.
- Exploit Prediction Scoring System data.
- MITRE ATT&CK techniques.
- AWS Security Hub findings.
- Amazon GuardDuty detections.
- Microsoft Defender for Cloud findings.
- Axonius-derived CAASM context.

## AI Architecture

The platform uses the OpenAI API for constrained, advisory security analysis.

Implemented principles include:

- Validated security context.
- Tenant-safe context construction.
- Structured analysis workflows.
- Explainable executive narratives.
- Remediation guidance.
- Human review before consequential decisions.
- No unchecked autonomous remediation.
- Separation of analysis from remediation authorization.

AI output must not override tenant boundaries, RBAC, or approval controls.

## Reporting Architecture

Implemented outputs include:

- Streamlit dashboards.
- Executive summaries.
- Client-specific reports.
- PDF exports.
- CSV exports.
- Risk scorecards.
- AI-assisted narratives.
- Remediation evidence views.
- Operational health history.

Reports must use tenant-scoped data and respect demo-mode sanitization.

## Remediation Architecture

The Execution Center provides controlled remediation workflows.

Implemented controls include:

- RBAC gating.
- Separate approval and execution permissions.
- Remediation plans and items.
- Guarded live actions.
- Initial live S3 remediation.
- HMAC-SHA256 evidence signing.
- Historical-key verification.
- Audit and execution outcome records.
- Rejection of unauthorized or unverified actions.

Live remediation is disabled by default:

`DGS_LIVE_REMEDIATION_ENABLED=false`

Future actions must preserve dry-run behavior, explicit approval, precondition checks, idempotency, failure evidence, and rollback planning.

## Persistence Architecture

The current platform uses multiple SQLite databases.

Primary databases include:

- `assets.db`
- `clients.db`
- `remediation.db`
- `users.db`
- `ai_assets.db`

Additional persistence supports:

- CAASM alerts.
- Operational monitoring.
- Remediation audit records.
- Remediation execution records.

Database paths use the configured DGS data directory. Docker uses `/data` as the persistent volume.

### Current Persistence Limitations

- No formal migration framework.
- No centralized schema-version registry.
- Runtime table initialization.
- Inline schema updates.
- Multiple independent database files.
- Incomplete default backup coverage.

SQLite is acceptable for the present engineering stage but is not an approved production-scale multi-tenant persistence architecture.

## Backup and Recovery

Current backup tooling covers:

- `assets.db`
- `clients.db`
- `remediation.db`

The following require explicit backup and restore coverage:

- `users.db`
- `ai_assets.db`
- CAASM alert data.
- Operational-monitoring data.
- Other required audit or execution data.

Backup creation is insufficient without restoration and integrity verification.

## External Integrations

Implemented integration areas include:

- AWS.
- Azure.
- OpenAI.
- Axonius.
- Splunk HEC.
- CISA KEV.
- NVD.
- EPSS.
- MITRE ATT&CK.

Email, Slack, Microsoft Teams, and generalized enterprise alert routing are planned rather than implemented.

## Container Architecture

The Docker image uses Python 3.13 slim Bookworm and runs Streamlit on port 8501.

Implemented hardening includes:

- Non-root `dgs` user.
- Fixed UID and GID 10001.
- `/data` persistent volume.
- Container health check.
- Read-only filesystem validation.
- Dropped Linux capabilities.
- `no-new-privileges`.
- Controlled writable temporary filesystems.
- Exclusion of secrets, databases, tests, documentation, backups, and generated artifacts.

## CI and Security Architecture

Protected `main` requires:

- Python 3.11.
- Python 3.13.
- Security Scanning.
- Hardened Docker Image.

The workflow performs dependency installation, `pip check`, selected-module compilation, automated testing, selected-module coverage enforcement, Bandit, pip-audit, detect-secrets, Docker build, non-root validation, image-configuration validation, and Streamlit health validation.

Current gaps include incomplete module compilation and selected-module rather than whole-production-code coverage.

## Operational Architecture

Implemented operational capabilities include:

- Application logging.
- Health checks.
- Operational health history.
- Health-alert evaluation.
- Backup and recovery tooling.
- Production smoke testing.
- Evidence-key validation.
- Splunk audit export.

Incomplete operational capabilities include:

- Infrastructure as code.
- Repeatable staging deployment.
- Centralized metrics and alerting.
- Incident-response runbook.
- Rollback procedure.
- Complete disaster-recovery exercise.
- Scheduled AWS and Azure scanning.
- Email, Slack, and Teams alerting.
- Defined service objectives.

## Critical Security Boundaries

1. Authentication.
2. Role and permission enforcement.
3. Tenant and client isolation.
4. Cloud credentials and AssumeRole.
5. AI context and output.
6. Remediation approval and execution.
7. Audit-evidence integrity.
8. Persistent data and backups.

Changes crossing these boundaries require explicit threat review and negative tests.

## Known Architecture Debt

1. Streamlit application monolith.
2. Forty-percent whole-production-code coverage.
3. Zero measured coverage for the active AssumeRole scan engine.
4. Multiple SQLite databases without formal migrations.
5. Incomplete backup scope.
6. Broad exception handling.
7. Unreferenced legacy scan engines.
8. Duplicate nested application directory.
9. Incomplete canonical documentation.
10. No infrastructure as code.
11. No complete staging operating model.
12. Incomplete scheduled scanning and alert routing.

## Architecture Direction

Phase 1 will stabilize and document the current platform without prematurely rewriting it.

Phase 2 will define and implement:

- Approved production datastore.
- Formal schema migrations.
- Infrastructure as code.
- Environment-specific deployment.
- Secrets management.
- Observability.
- Backup and restore validation.
- Incident and rollback procedures.
- Controlled staging deployment.

A separate API or service architecture should be considered only after domain boundaries are extracted from `app.py` and protected with tests.

## Capability Status

| Capability | Status |
| --- | --- |
| AWS cloud assessment | Implemented |
| AWS multi-account AssumeRole | Implemented |
| Tenant isolation | Implemented |
| Persistent authentication | Implemented |
| User administration | Implemented |
| RBAC | Implemented |
| AI-assisted analysis | Implemented |
| Executive reporting | Implemented |
| Guarded remediation | Implemented with limited live actions |
| Azure assessment | Implemented foundation; expanding |
| Splunk integration | Implemented |
| Axonius integration | Implemented and validated |
| Scheduled scanning | Planned |
| Generalized enterprise alerting | Partial |
| Formal database migrations | Not implemented |
| Infrastructure as code | Not implemented |
| Production-scale multi-client deployment | Not established |
