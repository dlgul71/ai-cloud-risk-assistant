"""Azure network exposure analysis utilities."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


INTERNET_SOURCE_PREFIXES = {
    "*",
    "internet",
    "0.0.0.0/0",
    "::/0",
}

CRITICAL_MANAGEMENT_PORTS = {
    "22",    # SSH
    "3389",  # RDP
    "5985",  # WinRM HTTP
    "5986",  # WinRM HTTPS
}


def _normalize(value: Any) -> str:
    """Return a stripped, lowercase string representation."""
    if value is None:
        return ""
    return str(value).strip().lower()


def _as_list(value: Any) -> list[Any]:
    """Convert a scalar or iterable value into a list."""
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, Iterable):
        return list(value)

    return [value]


def _get_source_prefixes(rule: dict[str, Any]) -> list[str]:
    """Return all source address prefixes configured on an NSG rule."""
    prefixes: list[Any] = []

    prefixes.extend(_as_list(rule.get("source_address_prefix")))
    prefixes.extend(_as_list(rule.get("source_address_prefixes")))

    return [_normalize(prefix) for prefix in prefixes if prefix is not None]


def _get_destination_ports(rule: dict[str, Any]) -> list[str]:
    """Return all destination ports or port ranges configured on a rule."""
    ports: list[Any] = []

    ports.extend(_as_list(rule.get("destination_port_range")))
    ports.extend(_as_list(rule.get("destination_port_ranges")))

    normalized_ports = [
        str(port).strip()
        for port in ports
        if port is not None and str(port).strip()
    ]

    return normalized_ports or ["*"]


def _is_internet_source(rule: dict[str, Any]) -> bool:
    """Determine whether an NSG rule accepts traffic from the internet."""
    return any(
        prefix in INTERNET_SOURCE_PREFIXES
        for prefix in _get_source_prefixes(rule)
    )


def _is_inbound_allow_rule(rule: dict[str, Any]) -> bool:
    """Return True when the rule permits inbound traffic."""
    return (
        _normalize(rule.get("direction")) == "inbound"
        and _normalize(rule.get("access")) == "allow"
    )


def _classify_exposure(
    ports: list[str],
) -> tuple[str, str]:
    """Return the exposure type and severity for exposed ports."""
    normalized_ports = {_normalize(port) for port in ports}

    if "*" in normalized_ports:
        return "ALL_PORTS_EXPOSED", "CRITICAL"

    if normalized_ports.intersection(CRITICAL_MANAGEMENT_PORTS):
        return "MANAGEMENT_PORT_EXPOSED", "CRITICAL"

    return "INTERNET_PORT_EXPOSED", "HIGH"


def _build_finding(
    network_security_group: dict[str, Any],
    rule: dict[str, Any],
    port: str,
    exposure_type: str,
    severity: str,
) -> dict[str, Any]:
    """Build a normalized Azure NSG exposure finding."""
    nsg_name = network_security_group.get("name", "Unknown NSG")
    rule_name = rule.get("name", "Unnamed Rule")

    return {
        "resource_id": network_security_group.get("id"),
        "resource_name": nsg_name,
        "resource_type": "AZURE_NETWORK_SECURITY_GROUP",
        "resource_group": network_security_group.get("resource_group"),
        "location": network_security_group.get("location"),
        "rule_name": rule_name,
        "priority": rule.get("priority"),
        "protocol": rule.get("protocol", "*"),
        "source_address_prefixes": _get_source_prefixes(rule),
        "port": port,
        "exposure_type": exposure_type,
        "severity": severity,
        "internet_exposed": True,
        "remediation": (
            f"Restrict inbound rule '{rule_name}' on NSG '{nsg_name}' "
            "to approved source IP ranges, private networks, Azure Bastion, "
            "a VPN, or a just-in-time access workflow."
        ),
    }


def analyze_network_security_groups(
    network_security_groups: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Analyze Azure NSGs for inbound rules exposed to the internet."""
    network_security_groups = network_security_groups or []

    findings: list[dict[str, Any]] = []
    analyzed_network_security_groups: list[dict[str, Any]] = []
    exposed_network_security_groups: set[str] = set()

    for index, network_security_group in enumerate(
        network_security_groups
    ):
        nsg_name = network_security_group.get(
            "name",
            f"Unnamed NSG {index + 1}",
        )
        rules = network_security_group.get("security_rules") or []
        nsg_findings: list[dict[str, Any]] = []

        for rule in rules:
            if not _is_inbound_allow_rule(rule):
                continue

            if not _is_internet_source(rule):
                continue

            ports = _get_destination_ports(rule)
            exposure_type, severity = _classify_exposure(ports)

            for port in ports:
                finding = _build_finding(
                    network_security_group=network_security_group,
                    rule=rule,
                    port=port,
                    exposure_type=exposure_type,
                    severity=severity,
                )
                findings.append(finding)
                nsg_findings.append(finding)

            exposed_network_security_groups.add(nsg_name)

        analyzed_network_security_groups.append(
            {
                **network_security_group,
                "internet_exposed": bool(nsg_findings),
                "finding_count": len(nsg_findings),
                "findings": nsg_findings,
            }
        )

    summary = {
        "network_security_groups": len(network_security_groups),
        "exposed_network_security_groups": len(
            exposed_network_security_groups
        ),
        "critical_findings": sum(
            finding["severity"] == "CRITICAL"
            for finding in findings
        ),
        "high_findings": sum(
            finding["severity"] == "HIGH"
            for finding in findings
        ),
        "medium_findings": sum(
            finding["severity"] == "MEDIUM"
            for finding in findings
        ),
    }

    return {
        "summary": summary,
        "findings": findings,
        "network_security_groups": analyzed_network_security_groups,
    }


def _public_ip_sku(public_ip_address: dict[str, Any]) -> str:
    """Return a normalized Azure public IP SKU name."""
    sku = public_ip_address.get("sku")

    if isinstance(sku, dict):
        sku = sku.get("name")

    return str(sku or "Unknown").strip()


def _public_ip_allocation_method(
    public_ip_address: dict[str, Any],
) -> str:
    """Return the public IP allocation method."""
    allocation_method = (
        public_ip_address.get("allocation_method")
        or public_ip_address.get("public_ip_allocation_method")
        or "Unknown"
    )

    return str(allocation_method).strip()


def _is_legacy_public_ip_configuration(
    allocation_method: str,
    sku: str,
) -> bool:
    """Identify legacy Basic SKU or dynamic public IP configurations."""
    return (
        _normalize(allocation_method) == "dynamic"
        or _normalize(sku) == "basic"
    )


def _build_public_ip_finding(
    public_ip_address: dict[str, Any],
    *,
    assigned: bool,
    allocation_method: str,
    sku: str,
) -> dict[str, Any]:
    """Build a normalized Azure public IP finding."""
    public_ip_name = public_ip_address.get(
        "name",
        "Unnamed Public IP",
    )

    if assigned:
        exposure_type = "ASSIGNED_PUBLIC_IP"
        severity = "HIGH"
        remediation = (
            f"Review whether public IP '{public_ip_name}' is required. "
            "Restrict inbound access with network security groups, "
            "Azure Firewall, approved source ranges, private endpoints, "
            "VPN access, or Azure Bastion."
        )
    else:
        exposure_type = "UNASSIGNED_PUBLIC_IP"
        severity = "MEDIUM"
        remediation = (
            f"Remove unassigned public IP '{public_ip_name}' if it is no "
            "longer required to reduce unused external attack surface "
            "and unnecessary Azure cost."
        )

    return {
        "resource_id": public_ip_address.get("id"),
        "resource_name": public_ip_name,
        "resource_type": "AZURE_PUBLIC_IP_ADDRESS",
        "resource_group": public_ip_address.get("resource_group"),
        "location": public_ip_address.get("location"),
        "ip_address": public_ip_address.get("ip_address"),
        "allocation_method": allocation_method,
        "sku": sku,
        "associated_resource_id": public_ip_address.get(
            "associated_resource_id"
        ),
        "associated_resource_type": public_ip_address.get(
            "associated_resource_type"
        ),
        "exposure_type": exposure_type,
        "severity": severity,
        "internet_exposed": assigned,
        "legacy_configuration": (
            _is_legacy_public_ip_configuration(
                allocation_method,
                sku,
            )
        ),
        "remediation": remediation,
    }


def analyze_public_ip_addresses(
    public_ip_addresses: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Analyze Azure public IP addresses and their associations."""
    public_ip_addresses = public_ip_addresses or []

    findings: list[dict[str, Any]] = []
    analyzed_public_ip_addresses: list[dict[str, Any]] = []

    assigned_count = 0
    unassigned_count = 0

    for index, public_ip_address in enumerate(public_ip_addresses):
        associated_resource_id = public_ip_address.get(
            "associated_resource_id"
        )
        assigned = bool(associated_resource_id)

        if assigned:
            assigned_count += 1
        else:
            unassigned_count += 1

        allocation_method = _public_ip_allocation_method(
            public_ip_address
        )
        sku = _public_ip_sku(public_ip_address)
        legacy_configuration = (
            _is_legacy_public_ip_configuration(
                allocation_method,
                sku,
            )
        )

        finding = _build_public_ip_finding(
            public_ip_address,
            assigned=assigned,
            allocation_method=allocation_method,
            sku=sku,
        )
        findings.append(finding)

        analyzed_public_ip_addresses.append(
            {
                **public_ip_address,
                "name": public_ip_address.get(
                    "name",
                    f"Unnamed Public IP {index + 1}",
                ),
                "allocation_method": allocation_method,
                "sku": sku,
                "internet_exposed": assigned,
                "assigned": assigned,
                "legacy_configuration": legacy_configuration,
                "exposure_type": finding["exposure_type"],
                "severity": finding["severity"],
            }
        )

    summary = {
        "public_ip_addresses": len(public_ip_addresses),
        "assigned_public_ip_addresses": assigned_count,
        "unassigned_public_ip_addresses": unassigned_count,
        "high_findings": sum(
            finding["severity"] == "HIGH"
            for finding in findings
        ),
        "medium_findings": sum(
            finding["severity"] == "MEDIUM"
            for finding in findings
        ),
    }

    return {
        "summary": summary,
        "findings": findings,
        "public_ip_addresses": analyzed_public_ip_addresses,
    }


def _resource_id(value: Any) -> str:
    """Return a normalized Azure resource ID."""
    if isinstance(value, dict):
        value = value.get("id")

    return _normalize(value)


def _resource_index(
    resources: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Create a case-insensitive Azure resource index by resource ID."""
    return {
        resource_id: resource
        for resource in resources
        if (resource_id := _resource_id(resource.get("id")))
    }


def _resource_ids(value: Any) -> list[str]:
    """Normalize a scalar or collection of Azure resource references."""
    return [
        resource_id
        for item in _as_list(value)
        if (resource_id := _resource_id(item))
    ]


def _virtual_machine_nic_ids(
    virtual_machine: dict[str, Any],
) -> list[str]:
    """Return network-interface IDs associated with a virtual machine."""
    nic_references: list[Any] = []

    nic_references.extend(
        _as_list(virtual_machine.get("network_interface_ids"))
    )
    nic_references.extend(
        _as_list(virtual_machine.get("network_interfaces"))
    )

    return _resource_ids(nic_references)


def _network_interface_public_ip_ids(
    network_interface: dict[str, Any],
) -> list[str]:
    """Return public-IP IDs associated with a network interface."""
    public_ip_references: list[Any] = []

    public_ip_references.extend(
        _as_list(network_interface.get("public_ip_address_id"))
    )
    public_ip_references.extend(
        _as_list(network_interface.get("public_ip_address_ids"))
    )

    return _resource_ids(public_ip_references)


def _network_interface_nsg_ids(
    network_interface: dict[str, Any],
) -> list[str]:
    """Return NSG IDs associated with a network interface."""
    nsg_references: list[Any] = []

    nsg_references.extend(
        _as_list(network_interface.get("network_security_group_id"))
    )
    nsg_references.extend(
        _as_list(network_interface.get("network_security_group_ids"))
    )

    return _resource_ids(nsg_references)


def _unique_strings(values: list[str]) -> list[str]:
    """Return strings in first-seen order without duplicates."""
    return list(dict.fromkeys(values))


def _vm_exposure_classification(
    exposed_ports: list[str],
) -> tuple[str, str]:
    """Classify an internet-facing virtual machine exposure."""
    normalized_ports = {_normalize(port) for port in exposed_ports}

    if "*" in normalized_ports:
        return "VM_ALL_PORTS_EXPOSED", "CRITICAL"

    if normalized_ports.intersection(CRITICAL_MANAGEMENT_PORTS):
        return "VM_MANAGEMENT_PORT_EXPOSED", "CRITICAL"

    return "VM_INTERNET_PORT_EXPOSED", "HIGH"


def _build_vm_exposure_finding(
    virtual_machine: dict[str, Any],
    *,
    public_ip_addresses: list[str],
    network_security_groups: list[str],
    exposed_ports: list[str],
    exposure_type: str,
    severity: str,
) -> dict[str, Any]:
    """Build a normalized internet-facing Azure VM finding."""
    vm_name = virtual_machine.get("name", "Unnamed Virtual Machine")

    if exposure_type == "PUBLIC_VM_WITHOUT_NSG":
        remediation = (
            f"Associate an appropriately restricted network security group "
            f"with virtual machine '{vm_name}' or its subnet. Remove the "
            "public IP when direct internet connectivity is unnecessary."
        )
    else:
        remediation = (
            f"Restrict internet-accessible inbound rules affecting virtual "
            f"machine '{vm_name}'. Use approved source ranges, Azure Bastion, "
            "VPN access, just-in-time VM access, private connectivity, or "
            "Azure Firewall."
        )

    return {
        "resource_id": virtual_machine.get("id"),
        "resource_name": vm_name,
        "resource_type": "AZURE_VIRTUAL_MACHINE",
        "resource_group": virtual_machine.get("resource_group"),
        "location": virtual_machine.get("location"),
        "public_ip_addresses": public_ip_addresses,
        "network_security_groups": network_security_groups,
        "exposed_ports": exposed_ports,
        "exposure_type": exposure_type,
        "severity": severity,
        "internet_exposed": True,
        "remediation": remediation,
    }


def analyze_internet_facing_virtual_machines(
    virtual_machines: list[dict[str, Any]] | None,
    network_interfaces: list[dict[str, Any]] | None,
    public_ip_addresses: list[dict[str, Any]] | None,
    network_security_groups: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Correlate Azure VMs, NICs, public IPs, and NSG exposure."""
    virtual_machines = virtual_machines or []
    network_interfaces = network_interfaces or []
    public_ip_addresses = public_ip_addresses or []
    network_security_groups = network_security_groups or []

    nic_index = _resource_index(network_interfaces)
    public_ip_index = _resource_index(public_ip_addresses)
    nsg_index = _resource_index(network_security_groups)

    findings: list[dict[str, Any]] = []
    analyzed_virtual_machines: list[dict[str, Any]] = []
    internet_facing_count = 0

    for index, virtual_machine in enumerate(virtual_machines):
        vm_name = virtual_machine.get(
            "name",
            f"Unnamed Virtual Machine {index + 1}",
        )

        associated_nics = [
            nic_index[nic_id]
            for nic_id in _virtual_machine_nic_ids(virtual_machine)
            if nic_id in nic_index
        ]

        associated_public_ips: list[str] = []
        associated_nsg_names: list[str] = []
        exposed_ports: list[str] = []
        associated_nsg_count = 0

        for network_interface in associated_nics:
            for public_ip_id in _network_interface_public_ip_ids(
                network_interface
            ):
                public_ip = public_ip_index.get(public_ip_id)

                if not public_ip:
                    continue

                ip_address = public_ip.get("ip_address")

                if ip_address:
                    associated_public_ips.append(str(ip_address))
                else:
                    associated_public_ips.append(
                        str(
                            public_ip.get(
                                "name",
                                public_ip.get("id", "Unknown Public IP"),
                            )
                        )
                    )

            for nsg_id in _network_interface_nsg_ids(network_interface):
                network_security_group = nsg_index.get(nsg_id)

                if not network_security_group:
                    continue

                associated_nsg_count += 1
                associated_nsg_names.append(
                    str(
                        network_security_group.get(
                            "name",
                            network_security_group.get(
                                "id",
                                "Unnamed NSG",
                            ),
                        )
                    )
                )

                for rule in (
                    network_security_group.get("security_rules") or []
                ):
                    if not _is_inbound_allow_rule(rule):
                        continue

                    if not _is_internet_source(rule):
                        continue

                    exposed_ports.extend(
                        _get_destination_ports(rule)
                    )

        associated_public_ips = _unique_strings(
            associated_public_ips
        )
        associated_nsg_names = _unique_strings(
            associated_nsg_names
        )
        exposed_ports = _unique_strings(exposed_ports)

        internet_exposed = bool(associated_public_ips)

        if internet_exposed:
            internet_facing_count += 1

            if associated_nsg_count == 0:
                finding = _build_vm_exposure_finding(
                    virtual_machine,
                    public_ip_addresses=associated_public_ips,
                    network_security_groups=[],
                    exposed_ports=[],
                    exposure_type="PUBLIC_VM_WITHOUT_NSG",
                    severity="HIGH",
                )
                findings.append(finding)

            elif exposed_ports:
                exposure_type, severity = (
                    _vm_exposure_classification(exposed_ports)
                )
                finding = _build_vm_exposure_finding(
                    virtual_machine,
                    public_ip_addresses=associated_public_ips,
                    network_security_groups=associated_nsg_names,
                    exposed_ports=exposed_ports,
                    exposure_type=exposure_type,
                    severity=severity,
                )
                findings.append(finding)

        analyzed_virtual_machines.append(
            {
                **virtual_machine,
                "name": vm_name,
                "network_interface_count": len(associated_nics),
                "public_ip_addresses": associated_public_ips,
                "network_security_groups": associated_nsg_names,
                "exposed_ports": exposed_ports,
                "internet_exposed": internet_exposed,
                "finding_count": sum(
                    finding["resource_name"] == vm_name
                    for finding in findings
                ),
            }
        )

    summary = {
        "virtual_machines": len(virtual_machines),
        "internet_facing_virtual_machines": internet_facing_count,
        "critical_findings": sum(
            finding["severity"] == "CRITICAL"
            for finding in findings
        ),
        "high_findings": sum(
            finding["severity"] == "HIGH"
            for finding in findings
        ),
        "medium_findings": sum(
            finding["severity"] == "MEDIUM"
            for finding in findings
        ),
    }

    return {
        "summary": summary,
        "findings": findings,
        "virtual_machines": analyzed_virtual_machines,
    }


def analyze_azure_network_exposure(
    network_security_groups: list[dict[str, Any]] | None,
    public_ip_addresses: list[dict[str, Any]] | None,
    network_interfaces: list[dict[str, Any]] | None,
    virtual_machines: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Run unified Azure NSG, public IP, and VM exposure analysis."""
    nsg_result = analyze_network_security_groups(
        network_security_groups
    )
    public_ip_result = analyze_public_ip_addresses(
        public_ip_addresses
    )
    virtual_machine_result = (
        analyze_internet_facing_virtual_machines(
            virtual_machines=virtual_machines,
            network_interfaces=network_interfaces,
            public_ip_addresses=public_ip_addresses,
            network_security_groups=network_security_groups,
        )
    )

    findings = [
        *nsg_result["findings"],
        *public_ip_result["findings"],
        *virtual_machine_result["findings"],
    ]

    summary = {
        "network_security_groups": nsg_result["summary"][
            "network_security_groups"
        ],
        "exposed_network_security_groups": nsg_result["summary"][
            "exposed_network_security_groups"
        ],
        "public_ip_addresses": public_ip_result["summary"][
            "public_ip_addresses"
        ],
        "assigned_public_ip_addresses": public_ip_result["summary"][
            "assigned_public_ip_addresses"
        ],
        "unassigned_public_ip_addresses": public_ip_result["summary"][
            "unassigned_public_ip_addresses"
        ],
        "virtual_machines": virtual_machine_result["summary"][
            "virtual_machines"
        ],
        "internet_facing_virtual_machines": (
            virtual_machine_result["summary"][
                "internet_facing_virtual_machines"
            ]
        ),
        "critical_findings": sum(
            finding.get("severity") == "CRITICAL"
            for finding in findings
        ),
        "high_findings": sum(
            finding.get("severity") == "HIGH"
            for finding in findings
        ),
        "medium_findings": sum(
            finding.get("severity") == "MEDIUM"
            for finding in findings
        ),
        "total_findings": len(findings),
    }

    return {
        "summary": summary,
        "findings": findings,
        "network_security_groups": nsg_result[
            "network_security_groups"
        ],
        "public_ip_addresses": public_ip_result[
            "public_ip_addresses"
        ],
        "virtual_machines": virtual_machine_result[
            "virtual_machines"
        ],
    }
