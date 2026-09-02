# Contributing to DGS Sentinel AI

## Purpose

This guide defines the engineering workflow for DGS Sentinel AI.

All changes must preserve security, tenant isolation, auditability, testability, and accurate product claims.

## Product Position

DGS Sentinel AI is a DGS-developed, production-oriented, multi-client security platform.

Do not describe the platform as deployed at production scale across multiple paying customers unless that status is independently verified and formally approved.

## Protected Branch

`main` is protected.

Changes to `main` must:

- Use a pull request.
- Pass required CI checks.
- Resolve review conversations.
- Avoid force pushes.
- Preserve repository history and security evidence.

Do not commit or push directly to `main`.

## Branch Workflow

Create a short-lived branch from an updated `main`.

Recommended branch patterns include:

- `phase-N-description`
- `feature/description`
- `fix/description`
- `security/description`
- `docs/description`
- `chore/description`

Phase branches matching `phase-*` run CI on push. All pull requests targeting `main` run required CI.

Before creating a branch:

1. Switch to `main`.
2. Fetch the remote.
3. Pull with `--ff-only`.
4. Confirm the working tree is clean.
5. Create the new branch.

Keep each branch focused on one coherent objective.

## Development Environment

Supported Python versions are:

- Python 3.11
- Python 3.13

Use a project virtual environment.

Install runtime and development dependencies from:

- `requirements.txt`
- `requirements-dev.txt`

Do not install unreviewed dependencies or modify pinned versions without explaining the need and security impact.

## Configuration

Copy `.env.example` to a local `.env` file and replace placeholders only in the untracked local file.

Never commit:

- `.env`
- Streamlit secrets.
- API keys.
- Cloud credentials.
- Access tokens.
- Private keys.
- HMAC evidence keys.
- Customer data.
- Local SQLite databases.
- Scan snapshots.
- Backup archives.
- Generated reports containing sensitive data.

Use placeholder values in tests and documentation.

## Required Local Validation

Before committing, run the checks relevant to the change.

The standard validation set includes:

- `python -m pytest -q`
- `python -m pip check`
- `python -m bandit` against tracked production Python.
- `python -m pip_audit -r requirements.txt -r requirements-dev.txt`
- `detect-secrets-hook --baseline .secrets.baseline` against tracked files.
- Python syntax validation.
- `git diff --check`

Do not weaken, bypass, or disable a security check to make a change pass.

A false positive must be reviewed and documented before the baseline or suppression is updated.

## Testing Standards

Every behavioral change requires tests.

Tests should cover:

- Expected behavior.
- Failure behavior.
- Invalid input.
- Unauthorized access.
- Cross-tenant access attempts.
- Empty and missing data.
- External-service failure.
- Retry or idempotency behavior where applicable.
- Audit and evidence behavior for consequential actions.

Bug fixes should include a regression test that fails before the fix and passes after it.

## Coverage Standards

The current whole-production-code baseline is 40%.

The existing CI threshold covers selected modules and must not be described as whole-platform coverage.

Coverage improvements should prioritize active critical paths:

1. Tenant isolation.
2. Authentication and authorization.
3. Active AWS AssumeRole scanning.
4. Remediation approval and execution.
5. Backup and restoration.
6. AI tenant-context construction.
7. Reporting and export.
8. Headless operations.

Do not inflate coverage by measuring tests, ignored backups, generated files, or obsolete code.

## Tenant-Isolation Requirements

Tenant isolation is a release-critical security boundary.

Changes involving clients, users, assets, findings, scans, AI context, reports, remediation, health data, or exports must verify:

- Authorized tenant access succeeds.
- Unauthorized tenant access fails.
- Global-administrator behavior is explicit.
- Tenant keys cannot be silently omitted.
- Exports contain only authorized tenant data.
- AI prompts and outputs remain tenant scoped.
- Database queries enforce the intended tenant boundary.

Never rely only on UI filtering for tenant protection.

## Authentication and RBAC Requirements

Changes must preserve:

- Password hashing.
- Account status enforcement.
- Account lockout.
- Session expiration.
- Authentication audit events.
- Role normalization.
- Permission checks.
- Global-administrator restrictions.

Legacy authentication fallback is disabled by default and must not become the preferred authentication path.

## Cloud Integration Standards

AWS and Azure integrations must:

- Use least-privilege credentials.
- Avoid logging credentials or tokens.
- Validate account or subscription identity.
- Handle unavailable services safely.
- Preserve tenant and client context.
- Bound retries and timeouts.
- Produce useful failure evidence.
- Avoid destructive behavior by default.

Cross-account AWS actions must maintain explicit STS AssumeRole boundaries.

## AI Security Standards

AI-related changes must:

- Use tenant-scoped context.
- Minimize sensitive data.
- Treat user and retrieved content as untrusted.
- Constrain prompt inputs.
- Validate structured outputs where used.
- Preserve human review.
- Keep AI analysis separate from remediation authorization.
- Avoid logging secrets or unnecessary prompt content.
- Test prompt-injection and context-leakage risks where applicable.

AI output is advisory and must not directly authorize a consequential action.

## Remediation Standards

Live remediation is disabled by default.

Remediation changes must preserve:

- Explicit permission checks.
- Separation of approval and execution.
- Allowlisted actions.
- Preconditions.
- Dry-run capability.
- Idempotency.
- Failure evidence.
- Audit records.
- Evidence integrity.
- Rollback planning.

A new live action requires targeted tests and a documented safety review.

## Database Standards

The current platform uses multiple SQLite databases without a formal migration framework.

Until a migration strategy is approved:

- Preserve backward compatibility.
- Test runtime schema initialization.
- Test upgrade behavior for existing databases.
- Use parameterized queries.
- Avoid unsafe dynamic SQL.
- Document every schema change.
- Update backup and restoration expectations.
- Preserve tenant keys and constraints.

Do not introduce another database file without architecture review.

## Backup and Recovery Standards

Changes to persistent data must identify:

- Whether the data requires backup.
- Retention expectations.
- Restoration procedure.
- Integrity checks.
- Encryption requirements.
- Tenant-isolation impact.
- Audit requirements.

A backup feature is not complete until restoration is tested.

## Exception-Handling Standards

Avoid broad `except Exception` handlers unless they are required at a deliberate application or integration boundary.

When broad handling is justified:

- Log useful diagnostic context.
- Do not log secrets.
- Preserve the original cause where practical.
- Return a clear safe failure.
- Avoid silently disabling security controls.
- Add tests for the failure path.

## Documentation Standards

Update documentation when a change affects:

- Architecture.
- Configuration.
- Security controls.
- Data storage.
- Deployment.
- Operations.
- User-visible behavior.
- Release status.
- Product claims.

Label capabilities accurately as implemented, partial, preview, or planned.

## Commit Standards

Use concise, imperative commit messages.

Examples include:

- `Add tenant-scoped scan history tests`
- `Document production backup requirements`
- `Fix unauthorized report export path`
- `Harden remediation evidence validation`

Do not combine unrelated refactoring, features, dependencies, and documentation in one commit.

## Pull Request Requirements

A pull request should include:

- Purpose and scope.
- Files or components affected.
- Security and tenant impact.
- Test evidence.
- Coverage impact.
- Configuration or migration impact.
- Deployment and rollback considerations.
- Documentation updates.
- Known limitations.
- Screenshots only when they add review value and contain no sensitive data.

## Definition of Done

A change is complete when:

- Acceptance criteria are satisfied.
- Tests pass.
- Security scans pass.
- Tenant boundaries are verified where applicable.
- Failure behavior is tested.
- Documentation is updated.
- Migration and backup impacts are addressed.
- Deployment and rollback effects are understood.
- Product claims remain accurate.
- The pull request passes all protected-branch requirements.

## Vulnerability Reports

Do not report vulnerabilities through public issues.

Follow `SECURITY.md` and use GitHub Private Vulnerability Reporting.
