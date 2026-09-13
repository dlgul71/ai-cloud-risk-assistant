# DGS Sentinel AI Release Procedure

**Status:** Controlled release procedure
**Current phase:** Phase 1 stabilization
**Release automation:** Manual
**Artifact publishing:** Source archives only

## Purpose

This procedure defines how DGS Sentinel AI release candidates, formal releases, and emergency fixes are prepared, reviewed, tagged, published, verified, and, when necessary, withdrawn.

A release records an approved source-code baseline. It does not by itself prove that the application has been deployed to production or operates at production scale across multiple paying customers.

Deployment and rollback are governed separately by the [Deployment and Rollback Runbook](DEPLOYMENT_AND_ROLLBACK.md).

## Release Principles

- Release only reviewed commits from protected `main`.
- Require every protected CI check to pass.
- Preserve tenant isolation, authentication, authorization, evidence integrity, and remediation guardrails.
- Keep AI output advisory and separate from remediation authorization.
- Keep live remediation disabled unless explicitly approved.
- Document migration, backup, restoration, configuration, and rollback impacts.
- Never include credentials, tokens, private keys, customer data, database files, backups, or sensitive reports in release artifacts.
- Record known limitations accurately.
- Never move or silently replace a published release tag.
- Do not represent an engineering milestone as customer production deployment.

## Release Types

| Type | Tag format | GitHub classification | Purpose |
| --- | --- | --- | --- |
| Release candidate | `vMAJOR.MINOR.PATCH-rc.N` | Prerelease | Controlled stabilization and validation |
| Formal release | `vMAJOR.MINOR.PATCH` | Release | Approved product release baseline |
| Patch release | `vMAJOR.MINOR.PATCH` | Release | Backward-compatible defect or security fix |
| Historical engineering milestone | Existing descriptive tags | Existing classification | Records earlier implementation or validation milestones |

New formal releases follow Semantic Versioning.

Historical descriptive tags remain part of the repository record but do not establish the naming convention for future formal releases.

## Version Selection

Increment:

- `MAJOR` for incompatible changes to supported behavior, persistent data, configuration, integrations, or operational contracts.
- `MINOR` for backward-compatible capabilities.
- `PATCH` for backward-compatible fixes and security updates.
- `rc.N` for a release candidate requiring additional validation.

If compatibility is uncertain, treat the change as release-critical and require explicit architecture review before choosing the version.

## Required Roles

| Role | Responsibility |
| --- | --- |
| Release owner | Coordinates scope, evidence, version, tag, and GitHub Release |
| Technical reviewer | Reviews implementation and operational effects |
| Security reviewer | Reviews security, tenant, dependency, and secret-scanning evidence |
| Data owner | Reviews schema, migration, backup, and restoration impacts |
| Release approver | Gives the final go or no-go decision |
| Deployment operator | Performs any separately authorized deployment |

During development, one person may hold multiple roles. For consequential production changes, approval and execution should be separated.

## Release Entry Criteria

A release may enter preparation only when:

- Its intended scope is defined.
- Acceptance criteria are available.
- Application behavior is accurately documented.
- Required implementation and documentation changes are complete.
- Known limitations are identified.
- Relevant tests pass.
- Tenant-boundary effects have been reviewed.
- Authentication and authorization effects have been reviewed.
- AI security effects have been reviewed where applicable.
- Remediation effects have been reviewed where applicable.
- Dependency and configuration changes are documented.
- Persistent-data changes have an approved migration and rollback approach.
- Required data is covered by backup and restoration planning.
- Deployment and rollback effects are understood.

## Release Blockers

Do not publish a release when any of the following applies:

- A required CI job is failing or incomplete.
- A committed secret or unreviewed secret-detection finding exists.
- A known exploitable dependency vulnerability remains without documented approval.
- A tenant-isolation, authentication, authorization, or global-administrator regression is unresolved.
- A schema change lacks tested upgrade and rollback behavior.
- Required persistent data lacks an approved backup and restoration path.
- Evidence authentication or integrity validation fails.
- Live remediation behavior changed without targeted safety testing and approval.
- Release notes overstate implementation, validation, deployment, or customer usage.
- The release commit is not the reviewed commit on protected `main`.
- Required reviewers have not approved the release.

A documented risk acceptance must identify the risk, impact, owner, expiration, compensating controls, and approving authority. Risk acceptance must never silently disable a security control.

## Prepare the Release Branch

Start from an updated protected branch:

```bash
git switch main
git fetch origin
git pull --ff-only origin main
git status --short
```

The working tree must be clean.

Create a short-lived release-preparation branch:

```bash
git switch -c release/vMAJOR.MINOR.PATCH
```

For a release candidate:

```bash
git switch -c release/vMAJOR.MINOR.PATCH-rc.N
```

The current workflow runs required CI for every pull request targeting `main`. A `release/*` branch may not run CI merely from being pushed, so the pull-request checks are authoritative.

## Prepare the Changelog

Update [CHANGELOG.md](../../CHANGELOG.md):

1. Create a new empty `Unreleased` section.
2. Move only included changes into the versioned release section.
3. Record the release date in `YYYY-MM-DD` format.
4. Separate additions, changes, fixes, security changes, and known limitations.
5. Identify migration, backup, configuration, and deployment impacts.
6. Preserve the distinction between implemented, partial, preview, and planned capabilities.
7. Do not claim production deployment or customer adoption without independent approval.

Do not use a release date until the release is actually approved for publication.

## Documentation Review

Review and update applicable documentation:

- [README](../../README.md)
- [Changelog](../../CHANGELOG.md)
- [V2 Roadmap](../../V2_ROADMAP.md)
- [Contribution Standards](../../CONTRIBUTING.md)
- [Current-State Architecture](../architecture/CURRENT_STATE.md)
- [Database Migration ADR](../architecture/ADR-0001-DATABASE-MIGRATION-STRATEGY.md)
- [Deployment and Rollback Runbook](DEPLOYMENT_AND_ROLLBACK.md)
- Security and integration documentation affected by the release

Release documentation must identify what changed, what remains incomplete, and all configuration, data, security, tenant, deployment, and rollback effects.

## Local Validation

Follow the validation requirements in [CONTRIBUTING.md](../../CONTRIBUTING.md).

At minimum, confirm:

```bash
python -m pip check

python -m pip_audit \
  -r requirements.txt \
  -r requirements-dev.txt

python -m pytest

detect-secrets-hook \
  --baseline .secrets.baseline \
  $(git ls-files)

git diff --check
git status --short
```

Run additional targeted tests for tenant isolation, authentication, authorization, database changes, backup and restoration, cloud integrations, AI tenant context, remediation safety, and every code path changed by the release.

Local success does not replace required GitHub CI.

## Release Pull Request

Commit release preparation separately from unrelated implementation:

```bash
git add CHANGELOG.md README.md V2_ROADMAP.md docs
git diff --cached --check
git diff --cached --stat
git commit -m "Prepare DGS Sentinel AI vMAJOR.MINOR.PATCH"
git push -u origin release/vMAJOR.MINOR.PATCH
```

Open a pull request into `main`.

The pull request must include:

- Release purpose and scope.
- Proposed version and classification.
- Included commits or workstreams.
- Security and tenant impact.
- Test and coverage evidence.
- Dependency-audit and secret-scan results.
- Configuration and migration impact.
- Backup and restoration impact.
- Deployment and rollback considerations.
- Documentation changes.
- Known limitations.
- Explicit go or no-go recommendation.

Do not merge until all review conversations are resolved and these checks pass:

- Python 3.11
- Python 3.13
- Security Scanning
- Hardened Docker Image

## Approve the Release

Before merge, the release approver must confirm:

- The proposed version is appropriate.
- Release scope matches the changelog.
- Required evidence is attached or linked.
- Known limitations are acceptable.
- No blocker remains open.
- Deployment is separately approved or explicitly out of scope.
- The rollback procedure is usable.
- Release claims are accurate.

Approval authorizes merging and tagging. It does not automatically authorize deployment or live remediation.

## Merge and Verify Protected Main

After the release pull request is merged:

```bash
git switch main
git fetch origin
git pull --ff-only origin main
git status --short
```

Verify that local `main` exactly matches the remote:

```bash
test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
git log -1 --oneline
```

Locate and watch the post-merge CI run:

```bash
gh run list \
  --workflow "DGS Sentinel AI CI" \
  --branch main \
  --limit 5

gh run watch RUN_ID --exit-status
```

Do not create the release tag until the post-merge `main` run succeeds.

Record the merge commit, pull-request number, CI run, CI conclusion, test result, security-scan result, release approver, and approval time.

## Create the Release Tag

Set and verify the intended tag:

```bash
release_tag="vMAJOR.MINOR.PATCH"

git check-ref-format "refs/tags/${release_tag}"
git tag --list "${release_tag}"
git tag --points-at HEAD
```

The proposed tag must not already exist.

Create an annotated tag:

```bash
git tag -a "${release_tag}" \
  -m "DGS Sentinel AI ${release_tag}"
```

If a verified signing key is configured, a signed tag is preferred:

```bash
git tag -s "${release_tag}" \
  -m "DGS Sentinel AI ${release_tag}"
```

Use either the annotated or signed command, not both.

Verify and push only the intended tag:

```bash
git show --no-patch --show-signature "${release_tag}"
test "$(git rev-list -n 1 "${release_tag}")" = "$(git rev-parse HEAD)"
git push origin "${release_tag}"
```

Never use `git push --tags` as part of the release procedure.

## Publish the GitHub Release

Release notes must include release classification, highlights, security and tenant effects, validation evidence, migration and backup impact, deployment status, known limitations, release commit, pull-request number, CI run, and changelog link.

For a release candidate:

```bash
gh release create "${release_tag}" \
  --verify-tag \
  --prerelease \
  --title "DGS Sentinel AI ${release_tag}" \
  --notes-file RELEASE_NOTES.md
```

For a formal release, omit `--prerelease`.

`RELEASE_NOTES.md` may be a temporary reviewed file. Do not commit it unless it is intentionally part of the repository documentation.

## Current Artifact Scope

The current GitHub Actions workflow builds and validates a hardened Docker image but does not publish it to a registry. It also does not publish an SBOM, signed artifact, build-provenance attestation, or deployment.

The current release therefore consists of:

- The Git tag.
- The GitHub Release record.
- GitHub-generated source archives.
- Linked validation evidence.

Do not claim that a release includes a published production container image.

## Verify the Published Release

```bash
gh release view "${release_tag}"

git ls-remote \
  --tags origin \
  "refs/tags/${release_tag}"
```

Confirm that the tag resolves to the approved `main` commit, the release classification is correct, the notes match the changelog, source archives are available, no sensitive data is exposed, and deployment status is accurate.

## Deployment Handoff

A published release is not automatically deployed.

Any deployment must follow the [Deployment and Rollback Runbook](DEPLOYMENT_AND_ROLLBACK.md) and record the environment, release tag, commit, authorization, backup readiness, configuration, migration decision, operator, validation results, and rollback outcome.

## Failed Release or Withdrawal

Do not silently move, overwrite, or delete a published tag.

If a release is defective:

1. Stop deployment or further rollout.
2. Record the affected tag and commit.
3. Assess security, tenant, data, and operational impact.
4. Follow the deployment rollback procedure where applicable.
5. Mark the GitHub Release as withdrawn or deprecated.
6. Explain the reason without disclosing sensitive exploit information.
7. Prepare a corrected patch release or release candidate.
8. Preserve the original tag and evidence for auditability.

Deleting a remote tag is exceptional and requires explicit maintainer approval, documented justification, and confirmation that no deployment or downstream consumer relies on it.

## Hotfix Procedure

A hotfix must:

1. Contain only the minimum safe correction.
2. Preserve tenant and security controls.
3. Include a regression test.
4. Update the changelog.
5. Complete protected pull-request review.
6. Pass every required CI check.
7. Merge through protected `main`.
8. Receive a new patch version.
9. Follow the standard tag and GitHub Release procedure.

Do not patch production manually without recording the corresponding reviewed source change.

## Security Release Procedure

For a non-public vulnerability:

- Follow `SECURITY.md`.
- Use GitHub Private Vulnerability Reporting.
- Limit access to the smallest necessary group.
- Avoid public issues and pull requests before coordinated disclosure.
- Prepare and validate the fix privately where supported.
- Rotate exposed credentials immediately when applicable.
- Assess tenant and customer-data impact.
- Publish only information approved for disclosure.
- Create a new immutable release tag for the fix.

## Release Evidence Record

Retain:

| Evidence | Required |
| --- | --- |
| Version and classification | Yes |
| Release commit and pull request | Yes |
| Approvals | Yes |
| CI run and job conclusions | Yes |
| Test and security evidence | Yes |
| Tenant review | Yes |
| Migration decision | Yes |
| Backup and restoration decision | Yes |
| Deployment and rollback decisions | Yes |
| Known limitations | Yes |
| Git tag and GitHub Release URL | Yes |

Release evidence must not contain secrets or unnecessary customer information.

## Current Limitations

The current release process does not yet provide:

- Automated release creation or changelog generation.
- A published container-registry artifact.
- Artifact signing, an SBOM, or build-provenance attestations.
- Automated staging deployment.
- Automated migration orchestration or rollback.
- A production deployment environment.

These limitations must remain visible until the corresponding capabilities are implemented and verified.

## Release Completion Criteria

A release is complete when:

- The release pull request is merged into protected `main`.
- Post-merge CI on `main` passes.
- The approved commit is tagged.
- The tag is pushed without being moved.
- The GitHub Release is published with accurate notes.
- Release evidence is recorded.
- Deployment status is stated accurately.
- Known limitations remain visible.
- Any separately authorized deployment has a documented outcome.
