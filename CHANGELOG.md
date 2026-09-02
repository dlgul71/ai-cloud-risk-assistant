# Changelog

All notable changes to DGS Sentinel AI will be documented in this file.

The project follows Keep a Changelog principles. Semantic versioning will be used for formal product releases after the current stabilization baseline is approved.

Release-readiness and validation tags describe engineering milestones. They do not by themselves represent commercial production deployment across multiple paying customers.

## Unreleased

### Added

- Persistent user authentication and user administration.
- Tenant-scoped client authorization.
- Tenant-scoped asset and remediation storage.
- Tenant-scoped executive, SOC, and asset dashboards.
- Tenant-aware AI analyst access controls.
- Tenant-safe OpenAI narrative context.
- Tenant-scoped AI asset storage and relationships.
- CI execution for v2 development branches.
- Reviewed secrets-baseline reconciliation.
- Phase 1 stabilization audit.
- Current-state architecture documentation.
- Coordinated vulnerability disclosure policy.
- Engineering contribution standards.

### Changed

- Merged v2.0 enterprise-operations and v2.1 AI-engineering work into protected `main` through pull request #23.
- Updated dependencies to remediate known vulnerabilities.
- Hardened tenant database queries for security scanning.
- Protected `main` with required pull requests and CI checks.
- Enabled GitHub Private Vulnerability Reporting.

### Security

- Enforced tenant boundaries across users, clients, assets, findings, dashboards, AI context, and remediation data.
- Strengthened persistent authentication, account lockout, and secure session management.
- Reconciled reviewed secret-detection findings.
- Verified Python 3.11, Python 3.13, security scanning, and hardened Docker validation after the v2 integration.

### Known Stabilization Work

- Whole-production-code coverage is 40%.
- The active AssumeRole scan engine has no measured coverage.
- CI compilation covers only selected production modules.
- SQLite persistence has no formal migration framework.
- Default backup scope is incomplete.
- `app.py` remains a large Streamlit monolith.
- Infrastructure as code and a repeatable staging environment are not implemented.
- Scheduled scanning and generalized enterprise alert routing remain incomplete.

## v2.0 Phase 3 - Tenant Dashboards - 2026-08-07

Tag: `v2.0-phase3-tenant-dashboards`

### Added

- Tenant-scoped executive dashboard access.
- Tenant-scoped SOC dashboard access.
- Tenant-scoped asset dashboard access.
- Regression protection for tenant-safe page data.

## v2.0 Phase 2 - User Administration - 2026-08-05

Tag: `v2.0-phase2-user-administration`

### Added

- Persistent authentication.
- Tenant authorization.
- Global user administration.
- User lifecycle and client-access management.

## v2.0 Phase 2 - Tenant Authorization - 2026-08-04

Tag: `v2.0-phase2-tenant-authorization`

### Added

- Tenant-scoped client authorization.
- Access assignment enforcement.
- Negative authorization tests.

## v2.0 Phase 2 - Authentication - 2026-08-04

Tag: `v2.0-phase2-authentication`

### Added

- Persistent application authentication.
- Secure session management.
- Authentication event recording.
- Account lockout and session expiration.

## v2.0 Phase 1 - Tenant Isolation - 2026-08-03

Tag: `v2.0-phase1-tenant-isolation`

### Added

- Stable tenant keys.
- Tenant isolation for asset storage and scans.
- Tenant isolation for remediation records.
- Tenant isolation for operational monitoring.

## v2.0 Phase 1 Start - 2026-07-30

Tag: `v2.0-phase1-start`

### Added

- Enterprise-operations roadmap covering tenant security, authentication, scheduled scanning, alerting, audit, compliance, and production operations.

## v1.9.0 - Production Readiness - 2026-07-30

Tag: `v1.9.0`

### Added

- Production-oriented configuration, health, backup, recovery, smoke-test, container, and operational controls.

### Clarification

This tag records an engineering readiness milestone. It does not establish production-scale deployment across multiple paying customers.

## v1.8 - Defender for Cloud Intelligence - 2026-07-27

Tag: `v1.8-defender-cloud-intelligence-validated`

### Added

- Validated Microsoft Defender for Cloud intelligence integration.

## v1.7 - CAASM Alerting - 2026-07-27

Tag: `v1.7-caasm-alerting-validated`

### Added

- Validated CAASM correlated-exposure alerting.

## v1.6 - Axonius Correlation - 2026-07-23

Tag: `v1.6-axonius-correlation-validated`

### Added

- Validated Axonius correlated-exposure analytics.

## v1.5 - Axonius CAASM - 2026-07-21

Tag: `v1.5-axonius-caasm-validated`

### Added

- Validated Axonius CAASM connector integration.

## v1.4 - Splunk HEC - 2026-07-17

Tag: `v1.4-splunk-hec-validated`

### Added

- Validated Splunk HTTP Event Collector integration.

## v1.3 - Azure NSG Remediation - 2026-07-16

Tag: `v1.3-azure-nsg-remediation-validated`

### Added

- Validated Azure network-security-group remediation.

## v1.2 - Azure Remediation - 2026-07-14

Tag: `v1.2-azure-remediation-validated`

### Added

- End-to-end Azure remediation validation.

## v1.1.0 - 2026-07-09

Tag: `v1.1.0`

### Added

- Role-based access control for Administrator, Analyst, and Viewer.
- Permission controls for scanning, client management, remediation, evidence, and health.

## v1.0.0 - 2026-07-09

Tag: `v1.0.0`

### Added

- Initial formal DGS Sentinel AI release baseline.
- Cloud-security visibility.
- Risk analytics.
- Executive reporting.
- AI-assisted analysis.
- Guarded remediation foundation.

## Earlier Engineering Milestones

Earlier tags record incremental delivery of:

- AWS asset and finding ingestion.
- Unified risk scoring.
- Executive dashboards.
- Risk trends.
- Remediation center.
- Guarded remediation simulation.
- CAASM snapshots and analytics.
- Public demo sanitization.
- Security scanning and CI enforcement.
- Live S3 remediation.
- Post-remediation verification.
- Structured remediation evidence.
- Tamper-evident evidence integrity.
- HMAC evidence authentication.
- Evidence-key rotation and verification.
- Deployment validation.
