# DGS Sentinel AI Deployment and Rollback Runbook

**Status:** Controlled deployment procedure
**Current phase:** Phase 1 stabilization
**Deployment model:** Single-instance Python or hardened Docker container
**Production-scale architecture:** Not yet approved
**Infrastructure as code:** Not yet implemented

## Purpose

This runbook defines the controlled steps for preparing, deploying, validating, and rolling back DGS Sentinel AI.

It documents the current engineering foundation. It does not represent the platform as highly available or deployed at production scale across multiple paying customers.

## Scope

This procedure covers:

- Release verification.
- Configuration and secret handling.
- Persistent-data preparation.
- Backup verification.
- Hardened Docker deployment.
- Python-based deployment where explicitly approved.
- Post-deployment validation.
- Rollback decision-making.
- Recovery evidence.

This procedure does not provide:

- Automated cloud infrastructure provisioning.
- High availability.
- Horizontal scaling.
- Automated database migration orchestration.
- Automated zero-downtime deployment.
- Managed TLS termination.
- A disaster-recovery environment.
- A production service-level agreement.

These capabilities require separate architecture approval.

## Required Roles

| Role | Responsibility |
| --- | --- |
| Release approver | Authorizes the release and deployment window |
| Deployment operator | Executes the documented procedure |
| Security reviewer | Confirms security controls and scan evidence |
| Data owner | Confirms backup scope and restoration readiness |
| Application validator | Verifies authentication, authorization, tenant isolation, and critical workflows |

One person may perform multiple roles during development or controlled testing, but approval and execution should be separated for consequential production changes.

## Safety Principles

- Deploy only reviewed commits from protected `main`.
- Require all protected CI checks to pass.
- Keep legacy authentication fallback disabled.
- Keep live remediation disabled unless separately authorized.
- Use least-privilege cloud credentials.
- Never place credentials in Git, command history, screenshots, logs, or deployment evidence.
- Preserve tenant identifiers and authorization boundaries.
- Stop deployment when backup, integrity, authentication, or tenant-isolation validation fails.
- Treat database schema changes as release-critical because no formal migration framework currently exists.
- Do not overwrite live database files while the application is running.

## Required Deployment Evidence

Record the following for every controlled deployment:

- Date and time.
- Operator.
- Approver.
- Environment.
- Release commit SHA.
- Release tag, if one exists.
- Pull-request number.
- Required CI run URL and conclusion.
- Container-image tag and image ID, when applicable.
- Configuration-change reference.
- Backup ID and verification result.
- Smoke-test result.
- Application-health result.
- Authorization and tenant-isolation validation.
- Deployment decision.
- Rollback decision, if applicable.
- Known warnings or limitations.

Do not include secrets, tokens, passwords, cloud evidence, or sensitive client data.

## Predeployment Requirements

Deployment must not begin until:

1. The release change has been merged through a protected pull request.
2. Python 3.11 CI has passed.
3. Python 3.13 CI has passed.
4. Security Scanning has passed.
5. Hardened Docker Image validation has passed.
6. The target commit has been recorded.
7. Configuration changes have been reviewed.
8. Persistent-data impact has been reviewed.
9. Backup scope has been approved.
10. A verified backup has been created.
11. The rollback image or prior source revision is available.
12. The rollback decision-maker is identified.
13. A maintenance window has been approved when service interruption is possible.

## Release Verification

Update the local deployment checkout using the approved operational process, then record:

```bash
git status --short
git rev-parse HEAD
git log -1 --oneline
```

The working tree must be clean.

Confirm that the recorded commit is the approved release commit and that its required GitHub Actions checks passed.

Do not deploy directly from an unreviewed feature branch.

## Configuration Review

Start from `.env.example` and obtain sensitive values from the approved secret-management process.

Required security defaults include:

```text
DGS_ALLOW_LEGACY_AUTH_FALLBACK=false
DGS_PUBLIC_DEMO_MODE=false
DGS_LIVE_REMEDIATION_ENABLED=false
```

Review at least:

- `APP_ENV`
- `LOG_LEVEL`
- `SESSION_TIMEOUT_MINUTES`
- `MAX_LOGIN_ATTEMPTS`
- `ACCOUNT_LOCKOUT_MINUTES`
- `AWS_REGION`
- `DGS_DATA_DIR`
- Azure subscription identity, when enabled
- Axonius endpoint and SSL verification, when enabled
- Splunk endpoint and SSL verification, when enabled
- Remediation-evidence signing configuration
- Live-remediation status

Production credentials must use password hashes or the approved persistent-user workflow. Plaintext legacy authentication must not become the preferred production path.

## Persistent Data

Most runtime data is rooted at `DGS_DATA_DIR`. The hardened container uses `/data`.

`caasm_alert_db.py` is a current exception: it resolves `caasm_alerts.db` relative to the process working directory. Do not assume that CAASM alert data is stored under `DGS_DATA_DIR`.

Known database domains include:

- `assets.db`
- `clients.db`
- `remediation.db`
- `operational_monitoring.db`
- `users.db`
- `ai_assets.db`
- `caasm_alerts.db`

The current default backup command includes:

- `assets.db`
- `clients.db`
- `remediation.db`
- `operational_monitoring.db`

The default backup set remains incomplete because it does not automatically include all known database domains.

Before deployment, identify every database required by the target environment.

## Backup Procedure

Create a default backup:

```bash
python -m scripts.backup_recovery_cli create
```

For an environment using additional databases, first verify that `DGS_DATA_DIR` is set to an absolute path:

```bash
if [ -z "${DGS_DATA_DIR:-}" ] || [ "${DGS_DATA_DIR#/}" = "$DGS_DATA_DIR" ]; then
  echo "DGS_DATA_DIR must be a nonempty absolute path." >&2
  exit 1
fi

printf 'Using persistent data directory: %s\n' "$DGS_DATA_DIR"
```

Then include each required database explicitly:

```bash
python -m scripts.backup_recovery_cli create \
  --database "${DGS_DATA_DIR}/assets.db" \
  --database "${DGS_DATA_DIR}/clients.db" \
  --database "${DGS_DATA_DIR}/remediation.db" \
  --database "${DGS_DATA_DIR}/operational_monitoring.db" \
  --database "${DGS_DATA_DIR}/users.db" \
  --database "${DGS_DATA_DIR}/ai_assets.db"
```

If CAASM alert persistence is used, determine and document the actual resolved path to `caasm_alerts.db` and include that path with a separate `--database` argument. Do not assume it is located under `DGS_DATA_DIR`.

A hardened read-only container deployment that requires CAASM alert persistence must not proceed until the writable storage path has been explicitly designed, tested, and approved.

If a listed database is not used in the target environment, document that determination rather than silently omitting it.

The command returns the backup ID and backup directory.

Verify the created package:

```bash
python -m scripts.backup_recovery_cli verify \
  PATH_TO_BACKUP_DIRECTORY
```

Deployment must stop if:

- Backup creation fails.
- A required database is missing unexpectedly.
- Manifest verification fails.
- A database integrity check fails.
- The backup destination lacks the required protection or capacity.
- Restoration has not been demonstrated for a schema-changing release.

## Restoration Test

Restore only into a new, empty destination:

```bash
python -m scripts.backup_recovery_cli restore \
  PATH_TO_BACKUP_DIRECTORY \
  --restore-root PATH_TO_EMPTY_RESTORE_DIRECTORY
```

Verify the restored files before approving the deployment.

Do not restore directly over active database files.

## Dependency and Application Validation

Before building the release:

```bash
python -m pip check

python -m pip_audit \
  -r requirements.txt \
  -r requirements-dev.txt

python -m pytest
```

The results must meet the release criteria documented in `CONTRIBUTING.md`.

## Docker Image Build

Use the approved full commit SHA as the immutable release identifier. A shortened SHA may be used as the local image tag if the full SHA is recorded in the evidence.

```bash
SENTINEL_RELEASE_TAG=$(git rev-parse --short=12 HEAD)

docker build \
  --tag "dgs-sentinel-ai:${SENTINEL_RELEASE_TAG}" \
  .
```

Record the image metadata:

```bash
docker image inspect \
  "dgs-sentinel-ai:${SENTINEL_RELEASE_TAG}" \
  --format 'Image ID: {{.Id}} User: {{.Config.User}}'
```

The configured image user must be `dgs`.

## Predeployment Container Test

Use an isolated temporary volume and a nonproduction port. Do not connect the test container to production cloud credentials or production databases.

```bash
docker volume create dgs-sentinel-preflight-data

docker run -d \
  --name dgs-sentinel-preflight \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /home/dgs:rw,noexec,nosuid,size=16m \
  --mount source=dgs-sentinel-preflight-data,target=/data \
  --env-file PATH_TO_APPROVED_NONPRODUCTION_ENV_FILE \
  -p 8502:8501 \
  "dgs-sentinel-ai:${SENTINEL_RELEASE_TAG}"
```

Validate the candidate:

```bash
python -m scripts.production_smoke_test \
  --base-url http://127.0.0.1:8502
```

Inspect health and logs:

```bash
docker inspect \
  --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}unavailable{{end}}' \
  dgs-sentinel-preflight

docker logs \
  --tail 200 \
  dgs-sentinel-preflight
```

The preflight deployment must not expose secrets or sensitive client data in logs.

After evidence is recorded, stop and remove only the named preflight resources using the approved cleanup process.

## Controlled Container Deployment

The approved runtime must retain these controls:

- Non-root execution.
- Read-only container filesystem.
- All Linux capabilities dropped.
- `no-new-privileges` enabled.
- Writable temporary filesystems only where required.
- Persistent `/data` storage.
- Approved environment configuration.
- Restricted network exposure.
- External TLS termination when remote access is allowed.

Example runtime structure:

```bash
docker run -d \
  --name dgs-sentinel-ai \
  --restart unless-stopped \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --tmpfs /home/dgs:rw,noexec,nosuid,size=16m \
  --mount source=dgs-sentinel-data,target=/data \
  --env-file PATH_TO_APPROVED_ENV_FILE \
  -p 127.0.0.1:8501:8501 \
  "dgs-sentinel-ai:${SENTINEL_RELEASE_TAG}"
```

Binding to `127.0.0.1` assumes access through an approved local reverse proxy or other controlled access layer. Do not expose the Streamlit port publicly without an approved network and TLS design.

## Python Deployment

A direct Python deployment may be used only where explicitly approved.

```bash
python -m pip install \
  --requirement requirements.txt

streamlit run app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --server.headless true
```

Use an operating-system service manager for controlled restart and log handling. Do not use an interactive terminal as the long-term production process supervisor.

## Postdeployment Smoke Test

Run:

```bash
python -m scripts.production_smoke_test \
  --base-url http://127.0.0.1:8501
```

Expected checks:

- Application root returns HTTP 200.
- Streamlit health endpoint returns `ok`.
- Container health becomes `healthy`, when using Docker.

## Application Validation

An authorized validator must confirm:

- Persistent administrator authentication works.
- Invalid authentication fails safely.
- Session expiration behaves as configured.
- Account lockout behaves as configured.
- Viewer access is read-only.
- Analyst access is limited to authorized clients and actions.
- Global-administrator access is restricted appropriately.
- Tenant A cannot access Tenant B data.
- Dashboard data respects tenant scope.
- AI context respects tenant scope.
- Report and export access respects tenant scope.
- Live remediation remains disabled unless explicitly approved.
- Cloud identities match the intended account or subscription.
- Optional integrations fail safely when unavailable.
- Logs contain no secrets or unnecessary sensitive data.

## Health Interpretation

A health result may contain warnings when optional integrations are not configured.

Deployment fails when a required component reports failure, including:

- Missing required authentication configuration.
- Unwritable persistent storage.
- Database-integrity failure.
- Missing required Python modules.
- Required integration failure.
- Missing remediation-evidence signing while live remediation is enabled.

Warnings must be documented and accepted by the release approver.

## Rollback Triggers

Initiate rollback when any of the following occurs:

- Authentication failure affecting authorized users.
- Unauthorized role or tenant access.
- Tenant-context leakage.
- Database-integrity failure.
- Required health or smoke-test failure.
- Repeated application startup failure.
- Material regression in scanning or reporting.
- Unexpected remediation behavior.
- Evidence-signing or audit failure.
- Unapproved schema modification.
- Exposure of secrets or sensitive client data.
- An unresolved severity-high or severity-critical security issue.
- The deployment exceeds the approved validation window.

## Rollback Decision Matrix

| Condition | Required response |
| --- | --- |
| Application failure with no persistent-data change | Restore the prior application image or revision |
| Configuration failure | Restore the last approved configuration and restart |
| Database integrity failure | Stop the application and begin verified recovery |
| Schema change without approved rollback | Stop deployment; do not continue |
| Tenant-isolation failure | Remove service access immediately and investigate |
| Suspected credential exposure | Remove access, rotate affected credentials, and begin incident response |
| Unauthorized remediation | Disable live remediation, preserve evidence, and investigate |

## Application Rollback

For a container-only rollback with no incompatible data change:

1. Stop the failed release.
2. Preserve its container logs and image identifier.
3. Start the previously approved image with the last approved configuration.
4. Reuse persistent data only when schema compatibility has been confirmed.
5. Run the smoke test.
6. Validate authentication and tenant isolation.
7. Record the rollback evidence.

Do not assume an older application image can safely use databases modified by a newer release.

## Data Recovery

When data restoration is required:

1. Stop all application instances using the affected databases.
2. Preserve the failed databases for investigation.
3. Verify the selected backup package.
4. Restore into a new, empty recovery directory.
5. Run SQLite integrity verification.
6. Confirm the backup contains every required database.
7. Confirm tenant keys and required records.
8. Obtain recovery approval.
9. Replace active data only through the approved recovery procedure.
10. Start the approved application version.
11. Run smoke, authentication, authorization, and tenant-isolation tests.
12. Record recovery evidence.

The current tooling does not provide automated atomic replacement of the live data directory.

## Post-Rollback Requirements

After rollback:

- Confirm the application health endpoint.
- Confirm persistent authentication.
- Confirm tenant authorization.
- Confirm database integrity.
- Confirm the intended cloud account or subscription.
- Confirm live remediation status.
- Preserve relevant logs and evidence.
- Document the root cause.
- Open corrective work through the protected-branch process.
- Do not retry the failed release without new review and approval.

## Deployment Completion Criteria

Deployment is complete only when:

- Required CI checks passed.
- The release commit and image are recorded.
- Backup creation and verification passed.
- Smoke testing passed.
- Authentication passed.
- Authorization and tenant isolation passed.
- Required integrations passed or approved warnings were documented.
- No unexpected database or schema behavior occurred.
- Live-remediation state matches the approved plan.
- Deployment evidence is complete.
- The release approver records acceptance.

## Known Limitations

- No infrastructure-as-code deployment exists.
- No formal staging environment exists.
- No formal schema-migration framework exists.
- Default backup coverage remains incomplete.
- CAASM alert persistence is not yet centralized under `DGS_DATA_DIR`.
- Recovery requires operator-controlled steps.
- High availability and automatic failover are not implemented.
- Centralized production observability is incomplete.
- Scheduled scanning is not implemented.
- A complete incident-response runbook remains pending.

These limitations must remain visible in release and customer-facing claims.
