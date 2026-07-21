# DGS Sentinel AI v1.5 — Axonius Connector Validation

## Validation Date

July 21, 2026

## Branch and Implementation

- Branch: `v1.5-development`
- Secure connector commit: `f9a1a8d`
- Connectivity health-check commit: `96af6e5`
- Configurable endpoint commit: `23d5144`

## Implemented Capabilities

DGS Sentinel AI v1.5 adds:

- Secure Axonius base URL and credential configuration
- Placeholder-value detection that prevents accidental live mode
- HTTPS-only base URL validation
- Rejection of embedded URL credentials
- Configurable asset and identity API endpoint paths
- Read-only asset and identity collection requests
- Configurable SSL verification and request timeout
- Mock-mode fallback when Axonius is not configured
- Controlled response-envelope parsing
- Optional Axonius connectivity check on the System Health page
- Safe configuration summaries that exclude API credentials

## Automated Validation

- Full test suite: `224 passed`
- Axonius connector and configuration tests passed
- Axonius health-check tests passed
- Bandit security scanning passed
- Detect-secrets scanning passed
- Python compilation checks passed
- Git diff validation passed

## Controlled Connector Validation

The connector request path was validated using injected HTTP responses without
requiring access to a production Axonius tenant.

The validation confirmed:

- HTTPS base URL normalization
- API key and API secret header construction
- Configurable asset endpoint selection
- Configurable identity endpoint selection
- SSL verification and timeout propagation
- Asset and identity response extraction
- HTTP error handling
- Invalid JSON handling
- Connection-error wrapping
- Positive-timeout enforcement
- System Health PASS, WARN, and FAIL states

This was controlled connector-path validation. It was not a live production
Axonius tenant test.

## Security Validation

- Axonius credentials are excluded from `AppSettings.safe_summary()`
- Placeholder values do not enable live mode
- HTTP base URLs are rejected
- Embedded URL credentials are rejected
- Endpoint paths must be relative paths beginning with `/`
- Absolute endpoint URLs are rejected
- SSL certificate verification defaults to enabled
- Request timeout defaults to 30 seconds
- Missing credentials return mock data rather than attempting live access
- Local secrets remain excluded from Git

## Safe Local Configuration

The local `.streamlit/secrets.toml` currently contains placeholder Axonius
values, so live Axonius access remains disabled.

- Axonius section present: `True`
- Base URL configured: `False`
- API key configured: `False`
- API secret configured: `False`
- Default asset path: `/api/assets`
- Default identity path: `/api/identities`
- SSL verification: enabled
- Timeout: 30 seconds

The endpoint paths are configurable because the correct routes may depend on
the Axonius tenant and API version.

## Conclusion

DGS Sentinel AI v1.5 successfully completed the secure Axonius connector
development and controlled validation lifecycle:

1. Secure configuration loading
2. Placeholder detection
3. HTTPS URL validation
4. Credential-header construction
5. Configurable endpoint selection
6. Asset and identity collection
7. Response-envelope validation
8. Controlled failure handling
9. Mock-mode fallback
10. Optional System Health connectivity checking
11. Automated security and regression testing

A live tenant validation should be completed only after authorized Axonius
service-account credentials and tenant-specific endpoint paths are available.
