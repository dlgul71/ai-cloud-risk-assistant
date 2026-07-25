# DGS Sentinel AI v1.7 — Correlated Exposure Alerting Validation

## Validation Date

July 24, 2026

## Branch and Implementation

- Branch: `v1.7-development`
- Alerting implementation commit: `2f45e99`
- Base release: `v1.6-axonius-correlation-validated`

## Implemented Capabilities

DGS Sentinel AI v1.7 adds:

- Critical and high correlated-exposure alert generation
- Stable SHA-256 alert fingerprints
- Alert deduplication by asset and source
- Persistent SQLite alert lifecycle storage
- Recurring-alert occurrence tracking
- Configurable notification cooldowns
- Alert notification-count tracking
- Successful-delivery timestamp tracking
- Alert acknowledgment
- Alert resolution with operator notes
- Automatic reopening of recurring resolved alerts
- Optional Splunk HEC delivery
- Partial-delivery failure reporting
- Role-based alert processing and management
- Dashboard alert metrics and lifecycle controls

## Alert Generation Model

Alert candidates are generated from v1.6 correlated-exposure rows.

Only the following priorities generate alerts:

- `CRITICAL`
- `HIGH`

Each alert includes:

- Stable fingerprint
- Alert type
- Title and message
- Priority
- Correlated risk score
- Asset ID
- Hostname
- Asset type
- Connector source
- Asset owner
- Risk drivers
- Lifecycle status

Moderate and standard correlation rows remain available for dashboard analytics
but do not create operational alerts.

## Alert Fingerprinting and Deduplication

The alert fingerprint is generated from:

- Event category
- Connector source
- Asset ID or hostname

Risk-score changes and risk-driver changes do not create duplicate alerts for
the same asset and source.

Recurring alerts:

- Increment `occurrence_count`
- Refresh `last_seen_at`
- Update the latest risk score and message
- Preserve acknowledgment state unless previously resolved
- Reopen automatically when a resolved exposure reappears

## Alert Lifecycle

Supported statuses are:

- `OPEN`
- `ACKNOWLEDGED`
- `RESOLVED`

Open alerts may be acknowledged by an authorized operator.

Open or acknowledged alerts may be resolved with:

- Resolution timestamp
- Resolving actor
- Resolution note

If the same fingerprint is detected after resolution, the alert returns to
`OPEN` status and its occurrence count increases.

## Notification Cooldown

Open critical and high alerts are eligible for notification when:

- They have never been sent, or
- Their configured cooldown period has expired

Acknowledged and resolved alerts are excluded from notification delivery.

The dashboard supports a configurable cooldown from zero minutes through seven
days.

Only successful deliveries update:

- `last_notified_at`
- `notification_count`

Failed Splunk deliveries remain eligible for a later delivery attempt.

## Splunk HEC Integration

Alert events use the existing secure Splunk HEC integration.

Each event contains:

- DGS Sentinel AI product metadata
- Alert event category
- Schema version
- Alert fingerprint
- Priority and status
- Asset and identity context
- Correlated risk score
- Risk drivers

Splunk delivery remains optional and requires:

- `SPLUNK_HEC_URL`
- `SPLUNK_HEC_TOKEN`

The existing Splunk index, source, sourcetype, TLS verification, and timeout
settings remain in effect.

## Role-Based Access

Alert processing uses the existing scan permission:

- `PERMISSION_RUN_SCANS`

Alert acknowledgment and resolution use the existing remediation-execution
permission:

- `PERMISSION_EXECUTE_REMEDIATION`

This preserves the existing DGS Sentinel AI RBAC model without introducing
unmanaged authorization paths.

## Dashboard Validation

The Axonius CAASM Dashboard now provides:

- Alert notification cooldown control
- Optional Splunk-delivery control
- Process Correlated Exposure Alerts action
- Open-alert count
- Acknowledged-alert count
- Resolved-alert count
- Alert lifecycle table
- Occurrence counts
- Notification counts
- Last-seen timestamps
- Last-notified timestamps
- Alert acknowledgment control
- Alert resolution control
- Resolution-note entry

## Automated Validation

- Full test suite: `254 passed`
- Alert-engine tests: `7 passed`
- Alert-database tests: `8 passed`
- Alert-service tests: `5 passed`
- Python compilation checks passed
- Git diff validation passed
- Bandit security scanning passed
- Detect-secrets scanning passed

## Controlled Alert Validation

Controlled tests confirmed:

- Stable fingerprint generation
- Critical and high alert creation
- Moderate alert filtering
- Priority and risk-score sorting
- Splunk event metadata
- Successful Splunk delivery reporting
- Failed Splunk delivery reporting
- Persistent alert creation
- Recurring-alert deduplication
- Occurrence-count updates
- Alert acknowledgment
- Alert resolution
- Resolved-alert reopening
- Notification cooldown enforcement
- Acknowledged-alert notification suppression
- Successful-delivery tracking
- Failed-delivery retry eligibility
- Empty and low-priority input handling

## Security Validation

- SHA-256 fingerprints contain no credentials
- Splunk tokens are not written to alert records
- Axonius credentials are not written to alert records
- Alert database records contain operational exposure context only
- Splunk credentials remain managed through application configuration
- Existing SSL-verification controls remain enabled by default
- Alert-management actions remain permission-controlled
- Bandit reported no security findings
- Detect-secrets reported no credential findings

## Validation Scope

Validation used controlled mock and unit-test asset, identity, connector, and
delivery data.

It did not:

- Access a production Axonius tenant
- Send events to a production Splunk deployment
- Validate tenant-specific Axonius field mappings
- Validate organization-specific SOC escalation procedures

Production validation requires authorized Axonius and Splunk credentials,
approved alert thresholds, operational cooldown settings, and documented SOC
ownership and escalation procedures.

## Conclusion

DGS Sentinel AI v1.7 successfully completed the controlled correlated-exposure
alerting lifecycle:

1. Correlation-row evaluation
2. Critical and high alert generation
3. Stable fingerprint creation
4. Persistent alert storage
5. Recurring-alert deduplication
6. Cooldown evaluation
7. Optional Splunk HEC delivery
8. Successful-delivery tracking
9. Alert acknowledgment
10. Alert resolution
11. Recurring-exposure reopening
12. Dashboard lifecycle management
13. RBAC enforcement
14. Automated regression and security testing
