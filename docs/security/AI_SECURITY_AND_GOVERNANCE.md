# DGS Sentinel AI Security and Governance Guide

**Status:** Controlled AI governance baseline
**Current phase:** Phase 1 stabilization
**AI role:** Advisory security analysis
**Autonomous consequential action:** Prohibited

## Purpose

This guide defines the security, privacy, tenant-isolation, human-review, change-control, testing, monitoring, and incident-response requirements for artificial-intelligence capabilities in DGS Sentinel AI.

It documents the current implemented foundation and the controls that must be completed before broader production use. It does not claim that the platform has completed an external AI assurance assessment or operates an autonomous security agent.

## Governing Principles

- AI output is advisory.
- AI output must not authorize or directly execute remediation.
- Authentication, authorization, tenant assignment, and permission enforcement remain deterministic application controls.
- Every AI request must use an explicit tenant boundary.
- Missing tenant scope must fail closed for tenant-scoped users.
- Global context is restricted to explicitly authorized global administrators.
- User, retrieved, stored, and model-generated content is untrusted.
- Only the minimum necessary data may be sent to a model provider.
- Secrets and credentials must never be included in prompts or outputs.
- High-impact decisions require accountable human review.
- Model, prompt, data-source, and provider changes require controlled review and testing.
- AI errors must fail safely without weakening security controls.
- Product documentation must distinguish implemented controls from planned controls.

## Scope

This guide applies to:

- Local analyst summaries.
- OpenAI-generated executive narratives.
- Tenant-scoped security-context construction.
- AI asset and relationship persistence.
- Prompt templates and system instructions.
- Model and provider configuration.
- Retrieved cloud, identity, finding, CAASM, and remediation data.
- AI-generated recommendations, summaries, reports, and exports.
- Future structured-output, retrieval, agent, tool, or automation features.

This guide applies whether AI is invoked from the Streamlit interface, a script, an API, a scheduled task, or a future service.

## Current Implementation Summary

| Control or capability | Current status |
| --- | --- |
| Tenant-scoped AI security context | Implemented foundation |
| Explicit global-administrator context path | Implemented |
| Empty tenant assignment returns no tenant data | Implemented and tested |
| Tenant-scoped assets and remediation data | Implemented and tested |
| Global CAASM comparison excluded from tenant prompts | Implemented and tested |
| Tenant-scoped AI assets and relationships | Implemented and tested |
| Grounded prompt instructions | Implemented |
| Limited top and persistent remediation lists | Implemented |
| Public-demo value substitution | Implemented, limited purpose |
| Local fallback when OpenAI is unavailable | Implemented |
| AI separated from remediation execution | Implemented policy and architecture |
| Structured model-output schema validation | Not implemented |
| Explicit model request timeout | Not implemented |
| Bounded retry policy | Not implemented |
| Formal prompt-injection regression suite | Not implemented |
| Formal model-quality evaluation suite | Not implemented |
| Comprehensive sensitive-data redaction | Not implemented |
| Persistent AI request and review audit trail | Not implemented |
| Approved production AI vendor assessment | Not documented |

## Implemented AI Architecture

The current OpenAI narrative path:

1. Receives the authenticated user's authorized client keys and global-administrator state.
2. Calls tenant-aware context construction.
3. Loads authorized assets and remediation records.
4. Excludes global CAASM snapshot comparisons for tenant-scoped users because those snapshots do not yet have an explicit tenant boundary.
5. Calculates executive metrics.
6. Limits top remediation and persistent-finding lists to ten items each.
7. Includes tenant-scope metadata in the grounded payload.
8. Applies public-demo value substitution when demo mode is enabled.
9. Instructs the model to use only supplied data, respect tenant scope, avoid invented data, and avoid claims that live remediation occurred.
10. Returns narrative text for human consumption.

The current provider integration uses:

- `OPENAI_API_KEY` from environment or approved application configuration.
- `OPENAI_MODEL` from environment configuration.
- `gpt-5.5` as the current code default.
- The OpenAI Responses API through the pinned OpenAI Python dependency.

Model availability, provider behavior, pricing, retention, and contractual terms may change independently of the repository. They must be reviewed before an approved production deployment.

## Current AI Data Sources

AI context may contain or summarize:

- Asset identifiers and types.
- AWS account identifiers.
- Regions.
- Hostnames.
- Private and public IP addresses.
- Asset state and risk scores.
- Findings and recommendations.
- Remediation priorities and status.
- Client names and tenant keys.
- Finding occurrence counts and timestamps.
- Identity-governance and CAASM metrics.
- Security-tool coverage information.
- AI asset metadata and relationships.

Not every available data field should be sent to an external model. Context construction must continue moving toward explicit allowlists and documented field-level necessity.

## AI Roles and Accountability

| Role | Responsibility |
| --- | --- |
| AI capability owner | Defines the use case, intended users, acceptable outputs, and success criteria |
| Data owner | Approves data sources, tenant scope, sensitivity, retention, and external processing |
| Security reviewer | Reviews threats, prompt controls, isolation, logging, testing, and failure behavior |
| Model reviewer | Evaluates model and prompt quality, grounding, stability, and known limitations |
| Human decision owner | Accepts or rejects advice and remains accountable for consequential decisions |
| Release approver | Confirms required evidence before releasing an AI change |
| Incident commander | Coordinates response to AI leakage, injection, misuse, or provider compromise |

The model is never an approver, administrator, security principal, or accountable decision owner.

## Permitted Use Cases

Permitted advisory uses include:

- Summarizing tenant-scoped security posture.
- Explaining grounded metrics and findings.
- Prioritizing existing findings for human review.
- Drafting executive narratives from supplied platform data.
- Identifying recurring unresolved findings from supplied occurrence data.
- Suggesting investigation questions.
- Drafting non-executable remediation guidance.
- Summarizing CAASM and identity-governance posture when the data is tenant safe.

Every permitted use remains subject to human verification.

## Prohibited Uses

AI must not:

- Authenticate a user.
- Assign a role, tenant, client, or permission.
- Decide whether a user is a global administrator.
- Approve, schedule, or execute remediation.
- Select arbitrary cloud credentials or targets.
- Bypass deterministic guardrails or preconditions.
- Modify audit or remediation evidence.
- Generate or reveal credentials, tokens, private keys, or evidence-signing keys.
- Retrieve another tenant's data.
- Make unsupported claims about threats, vulnerabilities, compliance, customers, or deployment status.
- Conceal uncertainty or fabricate source evidence.
- Serve as the sole basis for employment, legal, financial, safety, regulatory, or customer-notification decisions.
- Receive data for which external model processing has not been approved.

Future tool use or agentic behavior is prohibited until separately designed, threat modeled, approved, and tested.

## Data Classification and Handling

Classify proposed AI inputs before use:

| Data class | Example | External-model handling |
| --- | --- | --- |
| Public | Published documentation and public vulnerability identifiers | Allowed when relevant |
| Internal | Architecture summaries and non-sensitive operational metadata | Minimize and approve by use case |
| Security-sensitive | Findings, asset exposure, account identifiers, hostnames, IP addresses | Use only when necessary, tenant scoped, and approved |
| Restricted | Credentials, tokens, private keys, authentication secrets, evidence HMAC keys | Prohibited |
| Customer-regulated or contract-restricted | Customer data subject to legal, contractual, privacy, or residency requirements | Prohibited until explicit processing approval exists |

Public-demo substitution is not comprehensive de-identification. It replaces a defined set of known values only. Do not treat demo mode as a general privacy or sensitive-data redaction control.

## Data Minimization

Before constructing a prompt:

- Identify the decision or narrative the output must support.
- Include only fields required for that purpose.
- Prefer aggregated metrics over raw records.
- Limit record counts.
- Remove unused text, metadata, identifiers, and timestamps.
- Exclude secrets and credentials.
- Exclude unrelated tenants.
- Exclude raw logs unless specifically required and sanitized.
- Exclude full prompts or outputs from routine logs.
- Avoid persistent storage of prompts and responses unless an approved audit need exists.

Data minimization must occur before data is sent to the model provider, not only before output is displayed.

## Tenant-Isolation Requirements

Tenant isolation is a release-critical AI boundary.

Every tenant-scoped AI request must:

- Derive client access from the authenticated identity.
- Normalize and validate authorized client keys.
- Pass those keys to tenant-aware data-access functions.
- Return no tenant records when the authorized key set is empty.
- Prevent the model or user prompt from expanding scope.
- Keep assets, findings, remediation items, AI assets, and relationships within the same authorized boundary.
- Exclude sources without an explicit tenant key.
- Record enough non-sensitive scope metadata to investigate a boundary failure.

Only an explicitly verified global administrator may receive global context. A caller-supplied Boolean value is not sufficient authorization by itself; the application must derive administrator state from trusted authentication and authorization controls.

UI filtering is not a tenant-security control. Enforcement must occur in context construction and database access.

## Grounding Requirements

AI narratives must be grounded in supplied platform data.

Prompts must instruct the model to:

- Use only supplied facts.
- Avoid inventing assets, clients, findings, actions, or outcomes.
- Respect tenant scope.
- Distinguish observations from recommendations.
- State when required data is unavailable.
- Avoid claiming remediation execution.
- Preserve uncertainty.

Application code must not rely on prompt instructions alone. Deterministic data selection, tenant filtering, permissions, output handling, and action separation remain mandatory.

## Untrusted Content and Prompt Injection

Treat these as untrusted even when stored in a database:

- User questions.
- Asset names and descriptions.
- Findings and recommendations from external tools.
- Cloud tags and resource metadata.
- Axonius fields.
- Splunk content.
- Imported reports.
- Vulnerability descriptions.
- Model output.

Untrusted content may contain instructions intended to override the application prompt, disclose data, imitate trusted policy, or trigger unsafe action.

Controls must:

- Separate application instructions from untrusted content.
- Label retrieved content as data rather than instructions.
- Limit retrieved fields and length.
- Reject or neutralize unsupported control directives in data.
- Prevent prompt content from modifying tenant or permission scope.
- Validate any structured output against an allowlisted schema.
- Require human review before acting on recommendations.
- Test indirect prompt injection from every external data source used in AI context.

## Prompt Construction Standards

Prompt changes must be treated as code changes.

Each prompt must have:

- A defined purpose.
- An identified owner.
- Explicit tenant and data-source rules.
- An instruction hierarchy.
- Output expectations.
- Prohibited claims and actions.
- Bounded input size.
- Failure behavior.
- Tests for required and prohibited behavior.
- Version-control history.

Do not concatenate unrestricted user or retrieved text into a privileged instruction section.

## Output Handling

Current OpenAI output is free-form narrative text. It is not structurally validated.

Therefore:

- Treat every narrative as untrusted advisory text.
- Render it as text, not executable code or trusted HTML.
- Do not interpolate it into SQL, shell commands, cloud API parameters, file paths, or authorization decisions.
- Do not automatically convert recommendations into remediation requests.
- Do not represent model confidence as verified risk evidence.
- Require the reviewer to compare important claims with source data.
- Clearly label the output as AI generated.

If structured output is introduced, define a strict schema, reject additional fields, validate types and limits, fail closed on parse errors, and keep authorization outside the model response.

## Human Review

Human review is mandatory before AI output is used for:

- Executive reporting.
- Customer communication.
- Incident classification.
- Compliance assertions.
- Vulnerability prioritization that changes operational commitments.
- Remediation planning.
- Public documentation or marketing claims.
- Any consequential decision.

The reviewer must verify:

- Correct tenant and time period.
- Source-data accuracy.
- Unsupported or invented claims.
- Missing context.
- Sensitive-data exposure.
- Appropriate uncertainty.
- Separation between recommendation and authorization.

## Separation from Remediation

AI may recommend investigation or remediation priorities. It must not:

- Create approval on behalf of a user.
- Satisfy a permission check.
- Select a live credential.
- Override an allowlist.
- Confirm a precondition without deterministic verification.
- Execute a cloud action.
- Mark remediation evidence as verified.

Any future connection between AI output and the remediation workflow must require:

- Explicit permission checks.
- A separately authenticated human approval.
- Allowlisted actions and parameters.
- Tenant and cloud-identity binding.
- Dry-run capability.
- Preconditions and idempotency.
- Post-action verification.
- Tamper-evident audit records.
- Rollback planning.
- Targeted abuse and failure tests.

## Secrets and Provider Credentials

- Load `OPENAI_API_KEY` only through environment variables or an approved secret-management system.
- Keep populated `.env` and Streamlit secret files untracked.
- Never display or log the key.
- Never place the key in prompts, screenshots, test fixtures, or incident reports.
- Use separate credentials for development, testing, staging, and production where those environments exist.
- Restrict access to the smallest necessary operator group.
- Rotate the key after suspected exposure.
- Review provider usage and access evidence after exposure.

Placeholder keys may be used in tests only when they cannot authenticate to a live service.

## Model and Provider Change Control

A change to `OPENAI_MODEL`, the OpenAI dependency, the provider, endpoint, account, processing region, or retention configuration requires a reviewed pull request.

The change record must identify:

- Business purpose.
- Model and provider.
- Data classes processed.
- Tenant impact.
- Privacy, retention, residency, and contractual review.
- Security and abuse controls.
- Cost and rate-limit impact.
- Quality evaluation results.
- Failure and fallback behavior.
- Rollback procedure.

Do not assume a newer model is safer, more accurate, or compatible without evaluation.

## Request Limits and Reliability

The current integration does not explicitly configure a request timeout, retry policy, token budget, or output-length limit in application code.

Before production-scale use, implement and test:

- Explicit request timeouts.
- Bounded retries with backoff.
- Rate-limit handling.
- Input-size limits.
- Output-size limits.
- Cost controls.
- Cancellation behavior.
- Safe provider-unavailable behavior.
- Monitoring without logging sensitive prompt content.

Retries must not broaden tenant scope or duplicate consequential activity.

## Error Handling

The current OpenAI boundary catches broad exceptions and returns the exception string through the fallback result. This is a stabilization risk because provider or client errors may contain unnecessary diagnostic detail.

Required hardening:

- Log a sanitized error category and correlation identifier.
- Preserve the original cause in restricted diagnostics where appropriate.
- Return a safe user-facing failure message.
- Never return credentials, headers, prompt content, or sensitive tenant data.
- Distinguish configuration, authentication, timeout, rate-limit, provider, and validation failures.
- Test every failure path.
- Preserve the local grounded fallback without implying that the external narrative succeeded.

## Local Fallback

When OpenAI is not configured or fails, the platform may return a local grounded response.

The fallback must:

- Preserve the authenticated tenant boundary.
- Use only saved authorized platform data.
- Avoid unsupported claims.
- Clearly state that external model generation was unavailable.
- Remain advisory.
- Avoid silently changing security or remediation behavior.

Local fallback does not remove the need for tenant-scoped testing.

## AI Asset Governance

The AI asset database tracks AI assets and relationships using tenant keys.

Governance requirements include:

- Require `client_key` for every tenant-owned AI asset.
- Permit the same AI asset identifier in different tenants without collision.
- Scope relationship reads and writes by tenant.
- Validate asset type, name, provider, environment, status, and risk-score inputs.
- Record ownership and lifecycle state.
- Include `ai_assets.db` in approved backup and restoration scope.
- Apply the database migration strategy before schema evolution.
- Prevent global-administrator access from becoming an unreviewed export path.

Future inventory should distinguish models, agents, prompts, tools, data sources, providers, deployments, and owners.

## Logging and Audit

AI logging should record only what is necessary to investigate use and failure.

Preferred metadata includes:

- Timestamp.
- Authenticated user identifier.
- Tenant or approved global scope.
- Capability name.
- Prompt-template version.
- Model identifier.
- Sanitized request correlation identifier.
- Success or safe-failure category.
- Human-review status where required.

Do not routinely log:

- API keys.
- Full prompts.
- Full responses.
- Raw retrieved records.
- Credentials or authentication headers.
- Unnecessary hostnames, IP addresses, account identifiers, or customer data.

The current platform does not yet provide a complete persistent AI request and human-review audit trail. This remains planned work.

## Testing Requirements

Every AI change must test the behavior it affects.

Required categories include:

- Authorized tenant access succeeds.
- Unauthorized tenant access fails.
- Empty client assignments return no tenant data.
- Global context requires verified global-administrator state.
- Unscoped sources fail closed.
- AI assets and relationships remain tenant scoped.
- Prompt payloads exclude unrelated tenant data.
- Grounding instructions remain present.
- Secrets and prohibited fields are excluded.
- Public-demo substitution does not create a false claim of comprehensive redaction.
- Provider unavailability returns a safe fallback.
- Timeout and rate-limit failures are safe when those controls are added.
- Malformed or hostile output is rejected where structured output is used.
- AI output cannot authorize remediation.

## Prompt-Injection Test Cases

Use synthetic data to test at least:

- A user asks to ignore tenant restrictions.
- An asset name contains instructions to reveal another tenant.
- A finding description asks the model to disclose the system prompt.
- Retrieved content claims to be an administrator instruction.
- Content requests credentials or private keys.
- Content asks the model to create or execute remediation.
- Content attempts to override output format or safety rules.
- Content contains encoded or obfuscated instructions.
- Content attempts to exfiltrate other records through a summary.
- Content causes an oversized prompt or response.

Tests must verify deterministic scope and action controls, not merely whether the model verbally refuses.

## Model Evaluation

Before approving a model or material prompt change, evaluate it against a versioned synthetic dataset.

Measure:

- Tenant-boundary preservation.
- Grounded factual accuracy.
- Unsupported-claim rate.
- Omission of critical risks.
- Prioritization consistency.
- Prompt-injection resistance.
- Sensitive-data handling.
- Output usefulness.
- Failure and fallback behavior.
- Latency and cost.

Define acceptance thresholds before testing. Preserve evaluation configuration and results without storing prohibited sensitive data.

The current repository does not yet contain a formal model-evaluation framework or approved thresholds.

## Monitoring

Monitor, without exposing sensitive content:

- Request volume by capability and tenant boundary.
- Provider failures.
- Timeouts and rate limits.
- Fallback frequency.
- Input and output size.
- Cost anomalies.
- Human rejection or correction rate.
- Reports of hallucination, leakage, or unsafe advice.
- Model or configuration changes.
- Attempts to connect AI output to consequential actions.

Alerting must be tenant safe and must not place prompt or response content in broad notification channels.

## AI Incident Response

Treat prompt injection, cross-tenant context leakage, secret exposure, unsafe output handling, provider compromise, or excessive agency as security incidents.

Follow the [Incident Response and Recovery Runbook](../operations/INCIDENT_RESPONSE_AND_RECOVERY.md).

Initial AI containment may include:

- Disable the affected AI capability.
- Disable the external-provider integration.
- Preserve sanitized scope, prompt-template, model, and output evidence.
- Rotate an exposed provider key.
- Stop publication of affected reports.
- Confirm that no remediation action was authorized or executed by AI output.
- Test related tenant paths with synthetic data.

Report vulnerabilities privately under [SECURITY.md](../../SECURITY.md).

## Change and Release Requirements

An AI pull request must document:

- Use case and owner.
- Current and proposed behavior.
- Data sources and fields.
- Tenant and permission impact.
- Prompt and model changes.
- Provider and dependency changes.
- Human-review requirements.
- Threat model.
- Test and evaluation evidence.
- Logging and retention effects.
- Cost and reliability effects.
- Deployment and rollback plan.
- Known limitations.

The release must follow the [Release Procedure](../operations/RELEASE_PROCEDURE.md) and [Deployment and Rollback Runbook](../operations/DEPLOYMENT_AND_ROLLBACK.md).

## Production Approval Checklist

Before an AI capability is approved for production use, confirm:

- The use case is allowed and owned.
- Data processing is approved.
- Tenant isolation is deterministic and tested.
- Global-administrator behavior is explicit and tested.
- Prompt inputs are minimized and bounded.
- Secrets and prohibited data are excluded.
- Prompt injection is tested.
- Output handling is safe.
- Human review is defined.
- Consequential action remains separated.
- Timeouts, retries, rate limits, and cost controls are bounded.
- Errors are sanitized.
- Logging is sufficient and minimized.
- Provider, privacy, retention, residency, and contractual review is complete.
- Model evaluation meets predefined thresholds.
- Incident response and rollback are ready.
- Required CI and security checks pass.

Failure of any release-critical control blocks production approval.

## Current Limitations

The current AI foundation does not yet provide:

- Structured output validation.
- Explicit request timeouts and bounded retries.
- Formal input, output, token, and cost limits.
- Comprehensive sensitive-data discovery and redaction.
- A formal prompt-injection regression suite.
- A versioned model-quality evaluation framework.
- Persistent AI request and human-review audit records.
- Automated model-change detection.
- Documented production vendor, retention, residency, and contractual approval.
- Tenant-scoped CAASM snapshot comparison.
- Production-scale monitoring and alerting for AI use.

These limitations must remain documented until implemented and verified.

## Required Stabilization Work

1. Sanitize external-provider errors.
2. Add explicit timeout and bounded-retry behavior.
3. Add input, output, and cost limits.
4. Create a prompt-injection and context-leakage regression suite.
5. Define a versioned model-evaluation dataset and acceptance thresholds.
6. Implement an approved, minimized AI audit trail.
7. Create comprehensive data-field allowlists and sensitive-data controls.
8. Complete provider privacy, retention, residency, and contractual review.
9. Add explicit tenant boundaries to CAASM snapshots before tenant comparison.
10. Add AI monitoring and human-review metrics.

## Related Documents

- [Security Policy](../../SECURITY.md)
- [Contribution Standards](../../CONTRIBUTING.md)
- [Current-State Architecture](../architecture/CURRENT_STATE.md)
- [Database Migration Strategy](../architecture/ADR-0001-DATABASE-MIGRATION-STRATEGY.md)
- [Incident Response and Recovery Runbook](../operations/INCIDENT_RESPONSE_AND_RECOVERY.md)
- [Deployment and Rollback Runbook](../operations/DEPLOYMENT_AND_ROLLBACK.md)
- [Release Procedure](../operations/RELEASE_PROCEDURE.md)
- [Phase 1 Stabilization Audit](../development/PHASE_1_STABILIZATION_AUDIT.md)
- [Enterprise Operations Roadmap](../../V2_ROADMAP.md)

## Definition of Done

An AI change is complete when:

- Its use case, owner, data, model, and prompt are documented.
- Tenant and authorization boundaries are enforced and tested.
- Inputs are minimized and untrusted content is constrained.
- Outputs are safely handled and human reviewed.
- AI remains separated from consequential authorization and execution.
- Secrets and sensitive data are protected.
- Failure behavior is bounded and tested.
- Model and prompt evaluations meet approved criteria.
- Logging and evidence are sufficient without unnecessary content exposure.
- Incident, deployment, rollback, and release effects are addressed.
- Documentation accurately states implemented and remaining controls.
- Required CI and security checks pass.
