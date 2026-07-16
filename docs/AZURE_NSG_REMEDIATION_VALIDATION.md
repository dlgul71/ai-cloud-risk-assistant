# DGS Sentinel AI v1.3 — Azure NSG Remediation Validation

## Validation Date

July 15, 2026

## Test Resource

- Azure subscription: `0792ff8b-1860-475a-9310-56c73cd71572`
- Resource group: `dgs-sentinel-nsg-test-rg`
- Network Security Group: `dgs-sentinel-test-nsg`
- Security rule: `Allow-SSH-Internet`
- Remediation action ID: `45`
- Adapter: `AZURE_NSG_RULE_RESTRICTION`

## Initial Configuration

The temporary NSG rule allowed direct internet access to SSH:

- Access: `Allow`
- Direction: `Inbound`
- Protocol: `Tcp`
- Source: `Internet`
- Destination port: `22`
- Priority: `100`

## Initial Findings

- Network Security Groups analyzed: 1
- Exposed NSGs: 1
- Critical findings: 1
- High findings: 0
- Medium findings: 0
- Total findings: 1
- Exposure type: `MANAGEMENT_PORT_EXPOSED`

## Remediation Result

DGS Sentinel AI performed guarded live remediation by changing the exposed NSG rule from `Allow` to `Deny`.

The final Azure configuration was independently verified:

- Access: `Deny`
- Direction: `Inbound`
- Protocol: `Tcp`
- Source: `Internet`
- Destination port: `22`
- Priority: `100`
- Provisioning state: `Succeeded`

## Execution Evidence

- Execution status: `Completed`
- Execution mode: `Live`
- Verification status: `VERIFIED`
- Evidence authentication: `HMAC-SHA256`
- Request ID: `8eaaec99-3f61-4d34-b5a4-002e7d9d8fde`
- Verification request ID: `b09cf50a-7c66-4a2a-8572-ec81d29b3295`
- Evidence key ID: `acde8c8c2def294b`
- Evidence hash: `533fcf912be42ec100f61f0e4271b19db00b1bff880f57c9f794760cccbb750a`

The stored evidence hash matched the independently calculated HMAC hash.

## Post-Remediation Scan

- Network Security Groups analyzed: 1
- Exposed NSGs: 0
- Critical findings: 0
- High findings: 0
- Medium findings: 0
- Total findings: 0

## Guardrail Validation

The live remediation workflow required:

1. A saved Azure subscription binding
2. A validated NSG resource ID
3. The exact NSG security-rule name
4. Human approval
5. The live-execution confirmation phrase
6. An authenticated Azure Network Management client
7. Post-action retrieval and configuration verification
8. HMAC-SHA256 authenticated evidence storage

After validation, `DGS_LIVE_REMEDIATION_ENABLED` was removed from the environment and safe mode was confirmed as disabled.

## Conclusion

DGS Sentinel AI v1.3 successfully completed the Azure NSG remediation lifecycle:

1. Azure NSG discovery
2. Internet-exposure detection
3. Critical-risk classification
4. Subscription-bound remediation action creation
5. Human approval
6. Guarded live execution
7. Post-action verification
8. Tamper-evident evidence storage
9. Risk-reduction confirmation through rescanning

## Post-Validation Cleanup

After successful validation:

- Live remediation was returned to safe mode.
- The temporary resource group `dgs-sentinel-nsg-test-rg` was deleted.
- The temporary NSG `dgs-sentinel-test-nsg` was deleted with the resource group.
- The temporary rule `Allow-SSH-Internet` was deleted with the resource group.
- Final Azure resource-group verification returned `false`.
- The Azure subscription and existing credentials were preserved.
