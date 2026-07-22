# DGS Sentinel AI v1.6 — Axonius Correlated Exposure Validation

## Validation Date

July 22, 2026

## Branch and Implementation

- Branch: `v1.6-development`
- Correlated exposure analytics commit: `59a9168`
- Correlation snapshot trends commit: `489a19e`
- Correlation-aware recommendations commit: `b16012f`

## Implemented Capabilities

DGS Sentinel AI v1.6 adds:

- Asset-to-identity ownership correlation
- Case-insensitive identity matching
- Connector-source coverage correlation
- Correlated exposure risk scoring
- Critical, high, moderate, and standard prioritization
- Risk-driver explanations for every correlated asset
- Detection of unmatched asset owners
- Detection of unmanaged correlated assets
- Detection of assets connected to unavailable data sources
- Detection of privileged identities and MFA exceptions
- Detection of orphaned identities linked to assets
- Correlated exposure dashboard metrics
- Per-asset correlated risk visualization
- Correlated exposure CSV export
- Snapshot persistence for correlation metrics and records
- Correlation trend and delta reporting
- Snapshot-to-snapshot correlation comparison
- Correlation-aware executive recommendations

## Correlation Model

The v1.6 correlation engine combines:

- Asset risk score
- Identity risk score
- Asset management status
- Asset ownership
- Privileged-access status
- MFA status
- Orphaned-account status
- Connector availability
- Connector coverage percentage

The final correlated score is capped at `100`.

Priority levels are assigned as follows:

- `CRITICAL`: score of 85 or greater
- `HIGH`: score of 65 through 84
- `MODERATE`: score of 40 through 64
- `STANDARD`: score below 40

## Automated Validation

- Full test suite: `234 passed`
- Axonius risk-engine tests passed
- CAASM snapshot-engine tests passed
- Axonius connector tests remained passing
- Python compilation checks passed
- Bandit security scanning passed
- Detect-secrets scanning passed
- Git diff validation passed

## Controlled Correlation Validation

The correlation engine was validated using controlled asset, identity, and
connector-coverage records.

The validation confirmed:

- Asset owners are matched to identity records
- Username matching is case-insensitive
- Unmatched owners are identified
- Privileged identities increase correlated risk
- Identities without MFA increase correlated risk
- Orphaned identities increase correlated risk
- Unmanaged assets increase correlated risk
- Disconnected connector sources increase correlated risk
- Low connector coverage increases correlated risk
- Scores are capped at 100
- Results are sorted by priority and risk score
- Empty datasets return safe zero-value metrics
- Correlation metrics and rows persist in CAASM snapshots
- Older snapshot calls remain backward compatible
- Executive recommendations include critical correlated assets

## Dashboard Validation

The Axonius CAASM Dashboard now provides:

- Critical correlation count
- High correlation count
- Average correlated risk score
- Unmatched asset-owner count
- Unmanaged correlated-asset count
- Disconnected-source asset count
- Correlated exposure data table
- Correlated risk chart by asset
- Correlated exposure CSV download
- Correlated risk trend chart
- Correlation delta metrics
- Snapshot comparison export

## Snapshot Validation

CAASM snapshots now preserve:

- Correlation summary metrics
- Per-asset correlation rows
- Critical correlation counts
- High correlation counts
- Average correlated risk score
- Unmatched asset-owner counts

Existing snapshots without v1.6 correlation fields remain readable and safely
default to zero-value correlation metrics.

## Security Validation

- Correlation processing does not require additional credentials
- Axonius credentials remain excluded from safe configuration summaries
- No credentials are written to snapshots
- No credentials are included in CSV exports
- No credentials are included in executive recommendations
- Local secrets remain excluded from Git
- Bandit reported no security findings
- Detect-secrets reported no credential findings

## Validation Scope

Validation used controlled mock and unit-test datasets. It did not access a
production Axonius tenant.

Live tenant validation still requires authorized Axonius service-account
credentials, tenant-specific API paths, and production field-mapping review.

## Conclusion

DGS Sentinel AI v1.6 successfully completed the controlled Axonius correlated
exposure analytics lifecycle:

1. Asset and identity normalization
2. Asset-owner matching
3. Connector coverage matching
4. Multi-factor exposure scoring
5. Priority assignment
6. Risk-driver generation
7. Dashboard presentation
8. CSV export
9. Snapshot persistence
10. Trend and delta reporting
11. Executive recommendation generation
12. Automated regression and security testing
