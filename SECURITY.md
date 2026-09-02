# Security Policy

## Product Security Commitment

DGS Sentinel AI is a DGS-developed, production-oriented, multi-client cloud-security platform.

Security issues affecting authentication, tenant isolation, cloud credentials, AI context, remediation controls, audit evidence, or persistent data are treated as release-critical.

DGS Sentinel AI is not currently represented as deployed at production scale across multiple paying customers.

## Supported Versions

DGS Sentinel AI is under active development.

| Version | Security support |
| --- | --- |
| Current `main` branch | Supported |
| Active release candidate | Supported when identified |
| Historical development branches | Not supported |
| Older tags and archived phases | Not supported unless explicitly stated |

Security fixes are applied to the current supported development line. A formal long-term-support policy will be established before general production availability.

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Use GitHub Private Vulnerability Reporting:

https://github.com/dlgul71/ai-cloud-risk-assistant/security/advisories/new

Include as much of the following information as possible:

- A clear description of the vulnerability.
- The affected component or file.
- The tested commit, branch, or version.
- Reproduction steps.
- Proof-of-concept details.
- Expected and observed behavior.
- Potential security impact.
- Tenant-isolation implications.
- Required permissions or configuration.
- Relevant logs or screenshots with secrets removed.
- A suggested remediation, if available.

Never include real credentials, access tokens, private keys, customer data, or sensitive cloud identifiers in the report.

## Response Targets

DGS will make a reasonable effort to:

- Acknowledge a report within three business days.
- Complete initial triage within seven business days.
- Provide status updates during active remediation.
- Coordinate disclosure after a fix or acceptable mitigation is available.

Complex issues may require additional time. These targets are goals rather than contractual service-level agreements.

## Priority Security Boundaries

Reports involving the following areas receive elevated priority:

1. Authentication bypass.
2. Privilege escalation.
3. Cross-tenant data access.
4. Tenant-scope bypass.
5. Exposure of AWS, Azure, OpenAI, Axonius, or Splunk credentials.
6. Unauthorized scan execution.
7. Unauthorized remediation approval or execution.
8. Remediation evidence forgery or tampering.
9. SQL injection or unsafe query construction.
10. Sensitive-data leakage through AI prompts or outputs.
11. Demo-mode sanitization bypass.
12. Backup exposure or unauthorized restoration.
13. Remote code execution.
14. Dependency or container compromise.

## Testing Authorization

Good-faith testing must be limited to systems and data you own or are explicitly authorized to test.

Do not:

- Test against customer or third-party cloud environments.
- Access or modify another tenant's data.
- Perform denial-of-service testing.
- Use social engineering or phishing.
- Attempt physical intrusion.
- Introduce malware.
- Persist after demonstrating the issue.
- Exfiltrate sensitive data.
- Destroy, corrupt, or modify data.
- Publicly disclose an unresolved vulnerability.
- Use findings to threaten, extort, or demand payment.

Stop testing when sensitive information is encountered. Report the issue privately and remove locally retained sensitive information.

## Safe-Harbor Intent

DGS supports good-faith security research that:

- Follows this policy.
- Avoids privacy violations and service disruption.
- Uses only authorized systems and accounts.
- Reports findings promptly and privately.
- Provides reasonable time for remediation.
- Does not exploit the issue beyond what is necessary to demonstrate impact.

This policy does not authorize activity that violates applicable law or third-party rights.

## Secrets and Credentials

The repository must not contain live credentials.

Use environment variables or approved secret-management systems for:

- AWS credentials and role information.
- Azure tenant, client, and subscription credentials.
- OpenAI API keys.
- Axonius API credentials.
- Splunk HEC tokens.
- Remediation evidence HMAC keys.
- Application authentication secrets.

The populated `.env` file and Streamlit secrets must remain untracked.

If a live secret is committed:

1. Revoke or rotate it immediately.
2. Assess access logs and potential use.
3. Remove it from the current tree.
4. Determine whether repository history requires remediation.
5. Update the reviewed secrets baseline only after investigation.
6. Record the response without exposing the secret.

## Dependency and Build Security

Supported changes must pass:

- Python 3.11 tests.
- Python 3.13 tests.
- Bandit scanning.
- pip-audit.
- detect-secrets.
- `pip check`.
- Docker image build.
- Non-root container validation.
- Container health validation.

Known vulnerabilities must be remediated, mitigated, or explicitly risk-accepted before release.

## AI Security

AI-generated output is advisory.

AI workflows must:

- Use tenant-scoped context.
- Avoid sending unnecessary secrets or sensitive data.
- Treat retrieved and user-supplied content as untrusted.
- Validate security telemetry before analysis.
- Preserve human review.
- Prevent AI output from directly authorizing remediation.
- Log decisions without exposing sensitive prompt content.

Potential prompt injection, cross-tenant context leakage, insecure output handling, or excessive agency should be reported as security issues.

## Remediation Safety

Live remediation is disabled by default.

Security-sensitive remediation must preserve:

- Explicit authorization.
- Separate approval and execution permissions.
- Allowlisted actions.
- Preconditions.
- Dry-run support.
- Idempotency.
- Failure evidence.
- Audit records.
- Rollback planning.

## Disclosure

DGS will coordinate public disclosure after remediation or an agreed mitigation. Security advisories may credit reporters who request recognition.

DGS does not currently operate a paid bug-bounty program.
