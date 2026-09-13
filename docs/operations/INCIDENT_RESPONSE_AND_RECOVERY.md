# DGS Sentinel AI Incident Response and Recovery Runbook

**Status:** Controlled incident-response procedure
**Current phase:** Phase 1 stabilization
**Operating model:** Single-instance Python or hardened Docker deployment
**Production-scale incident program:** Not yet implemented

## Purpose

This runbook defines how DGS Sentinel AI security, privacy, availability, integrity, and persistent-data incidents are identified, contained, investigated, recovered, documented, and reviewed.

It applies to the current production-oriented engineering foundation. It does not represent a staffed 24-hour security operations center, a contractual response-time commitment, or a production-scale disaster-recovery capability.

Vulnerability reports are handled under [SECURITY.md](../../SECURITY.md). Deployment rollback is governed by the [Deployment and Rollback Runbook](DEPLOYMENT_AND_ROLLBACK.md).

## Objectives

- Protect tenant boundaries and customer information.
- Stop unauthorized access or consequential actions.
- Preserve reliable evidence.
- Restore trusted service and data safely.
- Minimize unnecessary exposure of sensitive information.
- Maintain separation between investigation, approval, and remediation execution.
- Record decisions, limitations, and recovery validation.
- Use incident findings to prevent recurrence.

## Safety Principles

- Protect people, credentials, tenant data, and evidence before restoring convenience.
- Treat suspected cross-tenant access as release-critical.
- Keep live remediation disabled unless separately authorized.
- Do not allow AI output to authorize containment, remediation, or recovery actions.
- Prefer reversible containment actions.
- Do not delete logs, databases, sessions, users, evidence, or cloud resources merely to simplify investigation.
- Never restore an unverified backup over active database files.
- Never expose credentials or sensitive customer data in tickets, chat, screenshots, logs, or incident reports.
- Use least-privilege access for investigation and recovery.
- Record who approved and performed each consequential action.
- Stop and escalate when authority, scope, tenant ownership, or recovery integrity is uncertain.

## Scope

This runbook covers incidents involving:

- Authentication and session controls.
- Tenant isolation and client authorization.
- User and administrator privileges.
- Cloud credentials and integration tokens.
- AI prompts, retrieved context, and tenant-scoped narratives.
- Remediation approval, execution, and evidence.
- SQLite databases and backup packages.
- Application configuration and secrets.
- Dependencies, source code, CI, and release integrity.
- Docker runtime and application availability.
- AWS, Azure, Axonius, Splunk, and other configured integrations.
- Logs, health checks, and operational-monitoring records.

This procedure does not replace legal, regulatory, insurance, law-enforcement, customer-contract, or cloud-provider notification requirements.

## Incident Definition

An incident is an observed or suspected event that threatens:

- Confidentiality of tenant, user, credential, or security data.
- Integrity of application data, audit evidence, releases, or remediation outcomes.
- Availability of the application or required persistent data.
- Authentication, authorization, or tenant-enforcement controls.
- Approved cloud-account or subscription boundaries.
- Safe and advisory use of AI capabilities.
- Ability to restore the platform to a trusted state.

A failed health check or integration call is not automatically a security incident. It becomes an incident when its cause, duration, recurrence, or impact threatens an objective above.

## Severity Classification

| Severity | Description | Examples | Handling priority |
| --- | --- | --- | --- |
| SEV-1 Critical | Confirmed or imminent high-impact compromise | Cross-tenant disclosure, active credential theft, unauthorized live remediation, widespread destructive data loss, compromised release | Immediate containment and executive escalation |
| SEV-2 High | Material suspected compromise or major service failure | Suspected tenant bypass, administrator compromise, evidence-integrity failure, major database corruption, prolonged outage | Urgent coordinated response |
| SEV-3 Moderate | Limited, contained, or recoverable incident | Single-tenant degradation, failed integration with bounded impact, recoverable backup failure | Prompt investigation and planned recovery |
| SEV-4 Low | Informational event or control weakness without current impact | Isolated warning, blocked attempt, documentation or monitoring gap | Track and correct through normal change control |

Severity may increase or decrease as evidence improves. Record every classification change and its reason.

These priorities are internal operating guidance, not contractual response-time guarantees.

## Required Roles

| Role | Responsibility |
| --- | --- |
| Incident commander | Coordinates response, scope, priorities, approvals, and communications |
| Technical lead | Investigates application, infrastructure, integrations, and data |
| Security lead | Directs containment, evidence handling, threat assessment, and disclosure coordination |
| Tenant or data owner | Assesses affected tenant data and recovery requirements |
| Recovery operator | Performs approved restoration or service-recovery actions |
| Communications owner | Maintains accurate internal and external status messages |
| Scribe | Records timeline, evidence, decisions, actions, and outcomes |

One person may fill multiple roles during development. Consequential production containment and recovery should preserve separation between approval and execution.

## Authority and Escalation

The incident commander may authorize reversible containment required to stop active harm. Destructive actions, production-data replacement, credential changes affecting unrelated systems, public disclosure, and live cloud remediation require the appropriate owner or approver.

Escalate immediately when:

- More than one tenant may be affected.
- An administrator or release credential may be compromised.
- Cloud credentials may permit write access.
- Unauthorized remediation may have executed.
- Audit or remediation evidence may be forged or altered.
- Required data cannot be recovered from a verified backup.
- Public disclosure, customer notification, or regulatory reporting may be required.
- The incident cannot be bounded confidently.

## Preparation Requirements

Before an incident occurs, maintain:

- Current responder and approver contact information.
- Secure access to GitHub, deployment systems, cloud providers, and secret-management systems.
- An inventory of application databases and their resolved paths.
- An inventory of cloud roles, service principals, API keys, and integration tokens.
- Verified backup manifests and restoration-test evidence.
- Protected copies of application configuration without secret values.
- Time synchronization for hosts and external services.
- Log-retention expectations.
- Documented health-check and smoke-test procedures.
- A method to communicate when the application or primary collaboration service is unavailable.

The current platform does not yet define approved recovery-time or recovery-point objectives. Do not invent them during an incident. Record actual data-loss exposure and recovery duration.

## Evidence Sources

| Source | Useful evidence |
| --- | --- |
| Structured application logs | Timestamp, logger, event, level, exception context, component |
| Authentication events | Login success or failure, lockout, session behavior, account changes |
| Tenant authorization records | Client assignments, tenant keys, permission decisions |
| `operational_monitoring.db` | Tenant-scoped health runs and component results |
| Health checks | Configuration, database integrity, storage, AWS identity, Splunk, and Axonius status |
| Remediation records | Request, approval, execution, verification, actor, target, and outcome |
| Remediation evidence | Integrity and authentication verification results |
| SQLite databases | Current application state and schema |
| Backup manifests | Included databases, checksums, missing databases, and creation time |
| Git and GitHub | Commits, pull requests, tags, releases, workflow runs, and security findings |
| Docker runtime | Image identity, configuration, health, state, and container logs |
| AWS and Azure logs | Identity, token use, API activity, account or subscription targets |
| Axonius and Splunk | Connector access, delivery attempts, and external-service audit evidence |

Confirm that every evidence source uses the correct time zone before correlating events.

## Detection Triggers

Begin triage when any of the following is observed:

- Cross-tenant data appears in a page, report, export, API response, AI narrative, or remediation record.
- Repeated authentication failures, unexpected lockouts, or suspicious sessions occur.
- An account gains unexpected role or client access.
- A credential or secret appears in Git, logs, reports, screenshots, or prompts.
- Cloud-provider activity occurs outside the approved account, subscription, role, or action.
- Live remediation is enabled unexpectedly or an unapproved action executes.
- Remediation evidence verification fails.
- Database integrity checks fail.
- A required database or backup file is missing.
- Backup checksum or restoration verification fails.
- The application or hardened container becomes unhealthy or repeatedly restarts.
- Dependency, secret, Bandit, or CI security scanning fails on a release path.
- AI output contains another tenant's context, follows hostile retrieved instructions, or attempts to authorize action.
- External integrations show unexpected authentication, delivery, or configuration changes.

## Initial Response Checklist

1. Open an incident record using a non-sensitive identifier.
2. Assign an incident commander and scribe.
3. Record the first observed time and reporting source.
4. Identify the affected environment, release tag, commit, tenant, user, and integration where known.
5. Classify the initial severity.
6. Preserve volatile evidence before restarting or reconfiguring services when safe.
7. Stop active harm using the least destructive effective containment.
8. Establish an approved communication channel.
9. Set the next review time.
10. Record every action, actor, approval, time, and result.

## Capture the Initial Technical State

Run only commands authorized for the affected environment. Do not print secret values.

For a Git checkout:

```bash
date -u
git branch --show-current
git rev-parse HEAD
git status --short
git tag --points-at HEAD
```

For Docker:

```bash
docker ps --no-trunc
docker inspect CONTAINER_NAME
docker logs --timestamps CONTAINER_NAME
```

Store collected output only in an approved evidence location. Sanitize secrets and unnecessary tenant data before sharing it.

Do not restart a container until volatile state and logs have been preserved, unless immediate restart is required to protect safety or prevent active harm.

## Triage Questions

Determine:

- What happened and how was it detected?
- Is the event ongoing?
- Which tenants, users, accounts, subscriptions, integrations, databases, and releases may be affected?
- Did confidentiality, integrity, or availability fail?
- Was authentication bypassed or a valid account misused?
- Did role, client assignment, or global-administrator state change?
- Did AI context cross a tenant boundary?
- Did any remediation action execute?
- Are credentials exposed or merely referenced?
- Are logs and audit records trustworthy?
- Is database integrity intact?
- What is the earliest and latest known affected time?
- What evidence would disprove or confirm the leading hypothesis?
- What containment action reduces risk without destroying evidence?

Do not declare an incident contained merely because alerts stop.

## Containment

Choose the smallest effective containment boundary.

Possible actions include:

- Disable or deactivate the affected user through supported administration controls.
- Revoke affected sessions where supported.
- Remove unauthorized client assignments or elevated roles through reviewed controls.
- Revoke and rotate an exposed credential.
- Disable an affected integration.
- Restrict network access to the service.
- Stop the affected application or container.
- Set `DGS_LIVE_REMEDIATION_ENABLED=false` and restart through approved deployment control.
- Suspend release or deployment activity.
- Block a compromised version from further rollout.
- Preserve affected databases as evidence and redirect recovery to isolated copies.

Do not:

- Delete an account instead of preserving its audit trail.
- Rewrite database rows directly without an approved, tested procedure.
- Delete a Git tag or release to conceal a bad version.
- Rotate unrelated credentials without understanding operational impact.
- Use AI-generated instructions as authorization.
- Execute cloud remediation outside the allowlisted, approved workflow.

## Tenant-Isolation Incident Playbook

For suspected cross-tenant access:

1. Treat the incident as at least SEV-2 until bounded.
2. Stop the affected data path, page, export, AI function, or service.
3. Preserve the requesting user, authenticated tenant, requested tenant, client key, permission, query path, and returned-record evidence.
4. Identify every consumer of the affected function.
5. Test whether the condition can expose more than one tenant.
6. Review dashboards, exports, reports, AI context, assets, findings, health records, and remediation records using the same path.
7. Do not use production customer data to reproduce the issue unless explicitly authorized.
8. Correct the boundary through a protected pull request with negative authorization tests.
9. Validate that Tenant A cannot access Tenant B before recovery approval.
10. Assess notification obligations for every potentially affected tenant.

## Credential-Exposure Playbook

For a suspected exposed credential:

1. Determine whether the value is real, active, privileged, and externally visible.
2. Revoke or disable the credential before relying on repository cleanup.
3. Create a replacement using least privilege.
4. Identify where the credential was stored, logged, transmitted, or used.
5. Review provider audit logs from before the earliest possible exposure.
6. Search the repository and generated artifacts for additional copies without printing the secret.
7. Assess whether Git history requires coordinated remediation.
8. Update configuration through the approved secret channel.
9. Validate the replacement without logging its value.
10. Record revocation, rotation, validation, and impact-assessment evidence.

Do not assume deleting a file or commit invalidates an exposed credential.

## Authentication or Privilege Incident Playbook

1. Preserve authentication and administration events.
2. Identify the user, roles, client assignments, session times, source, and affected actions.
3. Deactivate the account through supported controls when containment is required.
4. Revoke sessions where supported.
5. Reset credentials through the approved identity process.
6. Review administrator actions and client-access changes.
7. Confirm account-lockout and session-expiration controls remain active.
8. Verify legacy authentication fallback remains disabled.
9. Restore only the minimum required access.
10. Monitor renewed access for recurrence.

Avoid direct database edits unless the supported administration path is unavailable and an explicitly approved emergency procedure is documented.

## AI Security Incident Playbook

For prompt injection, context leakage, unsafe structured output, or excessive agency:

1. Disable the affected AI workflow or external-model integration if needed.
2. Preserve the tenant key, user, prompt source, retrieved-source identifiers, model configuration, and sanitized output.
3. Do not retain unnecessary prompt content or sensitive tenant data.
4. Determine whether untrusted content influenced instructions or structured output.
5. Test for cross-tenant context leakage using controlled fixtures.
6. Confirm AI output did not authorize or directly execute remediation.
7. Rotate the model-provider credential if it was exposed.
8. Add input constraints, output validation, and regression tests.
9. Require human security review before re-enabling the workflow.

## Remediation or Evidence Incident Playbook

1. Disable live remediation.
2. Preserve the remediation request, approval, actor, tenant, client, account or subscription, action, preconditions, execution result, and verification result.
3. Verify remediation-evidence integrity and authentication.
4. Review cloud-provider audit logs for the target and surrounding time period.
5. Confirm whether the action was allowlisted and correctly bound to its originating tenant and cloud identity.
6. Stop queued or repeated execution where supported.
7. Assess whether cloud-side rollback is safe and separately authorized.
8. Do not allow evidence correction to overwrite the original record.
9. Restore service only after permission, approval, idempotency, evidence, and verification controls pass.

## Database Corruption or Data-Loss Playbook

1. Stop application writes to the affected database.
2. Record the resolved database path and filesystem state.
3. Preserve a protected copy of the affected file before repair attempts.
4. Identify every affected tenant and data domain.
5. Determine the last known trusted backup.
6. Verify the backup manifest, checksums, and SQLite integrity.
7. Restore into a new empty location.
8. Validate schema, tenant keys, constraints, record counts, and application behavior.
9. Compare the restore point with the incident time to determine potential data loss.
10. Obtain approval before any production cutover.

Known database domains include:

- `assets.db`
- `clients.db`
- `remediation.db`
- `operational_monitoring.db`
- `users.db`
- `ai_assets.db`
- `caasm_alerts.db`
- Other required audit or execution data

The default backup set is incomplete. `caasm_alerts.db` also uses a process-relative path rather than the centralized data directory. Resolve and document every required database path before recovery.

## Backup Verification and Isolated Restore

Verify a candidate backup:

```bash
python -m scripts.backup_recovery_cli verify \
  PATH_TO_BACKUP_DIRECTORY
```

Choose a new, empty, approved restore directory. Do not use the active data directory.

```bash
python -m scripts.backup_recovery_cli restore \
  PATH_TO_BACKUP_DIRECTORY \
  --restore-root PATH_TO_EMPTY_RESTORE_DIRECTORY
```

Stop recovery when:

- The manifest is missing or unreadable.
- A required database is unexpectedly absent.
- A checksum fails.
- SQLite integrity validation fails.
- The restore destination is not empty.
- Backup custody or provenance is uncertain.
- The backup contains data outside the authorized tenant or environment scope.

Never overwrite the active database files while the application is running.

## Availability and Runtime Playbook

For an unhealthy or unavailable service:

1. Determine whether the failure is security-related, data-related, configuration-related, or operational.
2. Preserve container state and logs.
3. Confirm the deployed image, tag, and commit.
4. Confirm `DGS_DATA_DIR` resolves to the approved absolute persistent-data path.
5. Check storage capacity and permissions.
6. Run application health checks.
7. Check database integrity.
8. Review recent configuration, dependency, schema, and deployment changes.
9. Restart only through the approved service or container procedure.
10. Roll back using the deployment runbook when the current release cannot be trusted.

A successful Streamlit health endpoint proves basic process availability, not complete tenant, integration, data, or security health.

## Supply-Chain or Release Incident Playbook

1. Stop deployment of the affected commit, tag, dependency, action, or image.
2. Preserve CI runs, dependency reports, provenance information, and release metadata.
3. Identify every environment using the affected release.
4. Review whether the issue affects runtime or development-only dependencies.
5. Update the dependency or control through a protected pull request.
6. Run the complete required CI workflow.
7. Publish a new immutable patch or release-candidate tag.
8. Mark the affected GitHub Release as withdrawn or deprecated when necessary.
9. Do not silently move or replace the original tag.

## Cloud or External-Integration Playbook

1. Identify the exact AWS account, role, Azure tenant, client, subscription, Axonius tenant, Splunk endpoint, and credential involved.
2. Disable or revoke only the affected integration identity where possible.
3. Preserve provider audit logs and request identifiers.
4. Confirm least-privilege boundaries and token expiration.
5. Determine whether any write operation occurred.
6. Validate account or subscription identity before reconnecting.
7. Test recovery with controlled read-only access first.
8. Bound retries and timeouts to avoid amplifying the incident.
9. Keep credentials and tokens out of incident evidence.

## Eradication

Eradication removes the cause after containment and evidence preservation.

Required practices:

- Correct source code through a protected pull request.
- Add a regression test for the failure path.
- Replace compromised credentials.
- Remove unauthorized access through supported controls.
- Patch vulnerable dependencies.
- Correct unsafe configuration.
- Validate schema or data repair against isolated copies.
- Review related paths for the same weakness.
- Update documentation and runbooks.

Do not combine unrelated refactoring or new features with an incident fix.

## Recovery Approval

Recovery may begin only when:

- Active harm is contained.
- The recovery source is trusted.
- Required evidence is preserved.
- The release or corrective change passed required review and CI.
- Required backups are verified.
- Schema and migration behavior is understood.
- Credentials and configuration are ready.
- The deployment and rollback plan is approved.
- A recovery validator and decision owner are assigned.

## Recovery Validation

Validate, as applicable:

- Streamlit health endpoint.
- Container health and non-root runtime.
- Writable persistent-data paths.
- SQLite integrity.
- Authentication success and safe failure.
- Account lockout and session expiration.
- Role normalization and permission enforcement.
- Global-administrator restrictions.
- Tenant A cannot access Tenant B data.
- Dashboards, reports, exports, and AI context remain tenant-scoped.
- Cloud identities match the approved account, role, tenant, and subscription.
- External integrations fail safely.
- Live remediation remains disabled unless explicitly approved.
- Remediation evidence validates.
- Logs contain no secrets or unnecessary sensitive data.
- Backup monitoring resumes.

Use controlled test identities and synthetic data where practical.

## Return to Service

Restore service gradually:

1. Start in an isolated or controlled environment when available.
2. Validate critical controls before enabling user access.
3. Enable the smallest approved user or tenant scope.
4. Monitor authentication, authorization, health, database, and integration evidence.
5. Expand access only after validation remains stable.
6. Keep live remediation disabled unless separately approved.
7. Record the return-to-service decision and approver.

If monitoring or validation fails, stop expansion and return to containment or rollback.

## Communications

Every status update should state:

- Incident identifier and current severity.
- Confirmed facts.
- Unconfirmed hypotheses clearly labeled as such.
- Affected and unaffected scope where known.
- Containment and recovery status.
- Current risks and blockers.
- Decisions required.
- Time of the next update.

Do not include secret values, unnecessary customer data, sensitive prompt content, or unreviewed exploit details.

External notifications require approval and must be coordinated with applicable legal, contractual, regulatory, insurance, and vulnerability-disclosure requirements.

## Incident Timeline

Record events in UTC where practical:

| Time | Actor | Observation or action | Approval | Evidence | Result |
| --- | --- | --- | --- | --- | --- |
| `YYYY-MM-DDTHH:MM:SSZ` | Name or role | What occurred | Approver or N/A | Evidence reference | Outcome |

Do not alter earlier entries to make the timeline cleaner. Add corrections as new entries.

## Evidence Handling

- Assign stable evidence identifiers.
- Record source, collector, collection time, and integrity information.
- Preserve original files as read-only where practical.
- Work from copies.
- Restrict access by role and incident need.
- Encrypt evidence at rest and in transit.
- Keep tenant evidence separated.
- Sanitize evidence before broader sharing.
- Record transfers and transformations.
- Follow approved retention and deletion requirements.

Do not store incident evidence in the public repository.

## Incident Closure Criteria

An incident may close when:

- The cause and affected scope are understood to the approved confidence level.
- Active harm is contained.
- Required corrective changes are complete or formally tracked.
- Recovery validation passes.
- Tenant and security boundaries are verified.
- Credentials are rotated where required.
- Data-loss and restoration outcomes are documented.
- Required notifications are complete.
- Evidence is preserved according to policy.
- Residual risks have owners and due dates.
- The incident commander and required approvers accept closure.

Closure does not mean every long-term improvement is complete.

## Post-Incident Review

Complete a review after material incidents.

Document:

- Executive summary.
- Impact and affected scope.
- Detection source and detection delay.
- Technical and organizational timeline.
- Root cause and contributing factors.
- What contained the incident.
- What complicated response or recovery.
- Data-loss and service-interruption details.
- Security, tenant, AI, remediation, migration, and backup effects.
- Corrective actions with owners and due dates.
- Required test, monitoring, documentation, and architecture changes.
- Whether severity and communication decisions were appropriate.

Focus on system improvement and accountable action, not blame.

## Exercises and Recovery Drills

Exercise at least these scenarios before broader production use:

- Cross-tenant report or export exposure.
- Compromised administrator account.
- Exposed AWS, Azure, OpenAI, Axonius, or Splunk credential.
- Unauthorized remediation request or execution.
- Remediation-evidence verification failure.
- Corrupted `users.db` or `assets.db`.
- Incomplete backup during recovery.
- Unhealthy read-only Docker deployment.
- AI prompt injection or tenant-context leakage.
- Vulnerable dependency discovered after publication.

Each exercise should record detection, decisions, evidence, recovery time, data-loss exposure, validation, and improvement actions.

## Current Limitations

The current incident-response foundation does not yet provide:

- A staffed 24-hour response function.
- Contractual response-time commitments.
- Centralized enterprise logging and alert routing.
- Approved recovery-time and recovery-point objectives.
- Complete default backup coverage.
- Automated recovery orchestration.
- Formal schema migration execution.
- High availability or a disaster-recovery environment.
- Infrastructure as code.
- Automated evidence collection and chain-of-custody management.
- Production-scale incident and recovery exercises.

These limitations must remain visible until implemented and verified.

## Related Documents

- [Security Policy](../../SECURITY.md)
- [Contribution Standards](../../CONTRIBUTING.md)
- [Current-State Architecture](../architecture/CURRENT_STATE.md)
- [Database Migration Strategy](../architecture/ADR-0001-DATABASE-MIGRATION-STRATEGY.md)
- [Deployment and Rollback Runbook](DEPLOYMENT_AND_ROLLBACK.md)
- [Release Procedure](RELEASE_PROCEDURE.md)
- [Phase 1 Stabilization Audit](../development/PHASE_1_STABILIZATION_AUDIT.md)
- [Enterprise Operations Roadmap](../../V2_ROADMAP.md)

## Definition of Done

Incident response and recovery are complete for an event when:

- Scope, severity, and impact are documented.
- Active harm is contained.
- Evidence integrity is preserved.
- Root cause is corrected or residual risk is explicitly accepted.
- Recovery uses a trusted release, configuration, and data source.
- Tenant, authentication, authorization, AI, and remediation controls are validated.
- Required CI, health, integrity, backup, and restoration checks pass.
- Communications and notifications are complete.
- Recovery and closure are approved.
- Corrective actions are tracked through protected change control.
