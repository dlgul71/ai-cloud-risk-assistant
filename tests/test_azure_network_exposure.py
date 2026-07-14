from azure_network_exposure import analyze_network_security_groups


def test_detects_ssh_open_to_internet():
    network_security_groups = [
        {
            "id": "/subscriptions/test/resourceGroups/rg/providers/"
            "Microsoft.Network/networkSecurityGroups/web-nsg",
            "name": "web-nsg",
            "resource_group": "test-rg",
            "location": "eastus",
            "security_rules": [
                {
                    "name": "Allow-SSH",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 100,
                    "protocol": "Tcp",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "22",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["network_security_groups"] == 1
    assert result["summary"]["exposed_network_security_groups"] == 1
    assert result["summary"]["critical_findings"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["resource_name"] == "web-nsg"
    assert finding["rule_name"] == "Allow-SSH"
    assert finding["severity"] == "CRITICAL"
    assert finding["port"] == "22"
    assert finding["internet_exposed"] is True


def test_detects_rdp_open_to_azure_internet_prefix():
    network_security_groups = [
        {
            "name": "windows-nsg",
            "resource_group": "production-rg",
            "location": "centralus",
            "security_rules": [
                {
                    "name": "Allow-RDP",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 110,
                    "protocol": "Tcp",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "3389",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["critical_findings"] == 1
    assert result["findings"][0]["port"] == "3389"
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_detects_all_ports_open_to_internet():
    network_security_groups = [
        {
            "name": "open-nsg",
            "resource_group": "development-rg",
            "location": "westus2",
            "security_rules": [
                {
                    "name": "Allow-All-Inbound",
                    "access": "Allow",
                    "direction": "Inbound",
                    "priority": 100,
                    "protocol": "*",
                    "source_address_prefix": "*",
                    "destination_port_range": "*",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["critical_findings"] == 1
    assert result["findings"][0]["exposure_type"] == "ALL_PORTS_EXPOSED"
    assert result["findings"][0]["severity"] == "CRITICAL"


def test_ignores_outbound_allow_rules():
    network_security_groups = [
        {
            "name": "outbound-nsg",
            "security_rules": [
                {
                    "name": "Allow-Outbound",
                    "access": "Allow",
                    "direction": "Outbound",
                    "source_address_prefix": "*",
                    "destination_port_range": "*",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["network_security_groups"] == 1
    assert result["summary"]["exposed_network_security_groups"] == 0
    assert result["summary"]["critical_findings"] == 0
    assert result["findings"] == []


def test_ignores_denied_inbound_rules():
    network_security_groups = [
        {
            "name": "deny-nsg",
            "security_rules": [
                {
                    "name": "Deny-SSH",
                    "access": "Deny",
                    "direction": "Inbound",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "22",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["exposed_network_security_groups"] == 0
    assert result["findings"] == []


def test_ignores_private_source_ranges():
    network_security_groups = [
        {
            "name": "private-nsg",
            "security_rules": [
                {
                    "name": "Internal-SSH",
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "10.0.0.0/8",
                    "destination_port_range": "22",
                }
            ],
        }
    ]

    result = analyze_network_security_groups(network_security_groups)

    assert result["summary"]["exposed_network_security_groups"] == 0
    assert result["findings"] == []


def test_returns_empty_result_for_no_network_security_groups():
    result = analyze_network_security_groups([])

    assert result == {
        "summary": {
            "network_security_groups": 0,
            "exposed_network_security_groups": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
        },
        "findings": [],
        "network_security_groups": [],
    }


from azure_network_exposure import analyze_public_ip_addresses


def test_detects_assigned_public_ip_address():
    public_ip_addresses = [
        {
            "id": (
                "/subscriptions/test/resourceGroups/prod-rg/providers/"
                "Microsoft.Network/publicIPAddresses/web-public-ip"
            ),
            "name": "web-public-ip",
            "resource_group": "prod-rg",
            "location": "eastus",
            "ip_address": "203.0.113.10",
            "allocation_method": "Static",
            "sku": "Standard",
            "associated_resource_id": (
                "/subscriptions/test/resourceGroups/prod-rg/providers/"
                "Microsoft.Network/networkInterfaces/web-nic"
            ),
            "associated_resource_type": "NETWORK_INTERFACE",
        }
    ]

    result = analyze_public_ip_addresses(public_ip_addresses)

    assert result["summary"]["public_ip_addresses"] == 1
    assert result["summary"]["assigned_public_ip_addresses"] == 1
    assert result["summary"]["unassigned_public_ip_addresses"] == 0
    assert result["summary"]["high_findings"] == 1
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["resource_name"] == "web-public-ip"
    assert finding["ip_address"] == "203.0.113.10"
    assert finding["severity"] == "HIGH"
    assert finding["exposure_type"] == "ASSIGNED_PUBLIC_IP"
    assert finding["internet_exposed"] is True


def test_detects_unassigned_public_ip_address():
    public_ip_addresses = [
        {
            "name": "unused-public-ip",
            "resource_group": "development-rg",
            "location": "westus2",
            "ip_address": "198.51.100.20",
            "allocation_method": "Static",
            "sku": "Basic",
            "associated_resource_id": None,
        }
    ]

    result = analyze_public_ip_addresses(public_ip_addresses)

    assert result["summary"]["public_ip_addresses"] == 1
    assert result["summary"]["assigned_public_ip_addresses"] == 0
    assert result["summary"]["unassigned_public_ip_addresses"] == 1
    assert result["summary"]["medium_findings"] == 1

    finding = result["findings"][0]

    assert finding["resource_name"] == "unused-public-ip"
    assert finding["severity"] == "MEDIUM"
    assert finding["exposure_type"] == "UNASSIGNED_PUBLIC_IP"
    assert finding["internet_exposed"] is False


def test_detects_dynamic_basic_public_ip():
    public_ip_addresses = [
        {
            "name": "legacy-public-ip",
            "resource_group": "legacy-rg",
            "location": "centralus",
            "ip_address": "192.0.2.15",
            "allocation_method": "Dynamic",
            "sku": "Basic",
            "associated_resource_id": (
                "/subscriptions/test/resourceGroups/legacy-rg/providers/"
                "Microsoft.Network/networkInterfaces/legacy-nic"
            ),
            "associated_resource_type": "NETWORK_INTERFACE",
        }
    ]

    result = analyze_public_ip_addresses(public_ip_addresses)

    assert result["summary"]["high_findings"] == 1

    public_ip = result["public_ip_addresses"][0]

    assert public_ip["internet_exposed"] is True
    assert public_ip["legacy_configuration"] is True
    assert public_ip["allocation_method"] == "Dynamic"
    assert public_ip["sku"] == "Basic"


def test_supports_load_balancer_public_ip_association():
    public_ip_addresses = [
        {
            "name": "frontend-public-ip",
            "resource_group": "network-rg",
            "location": "eastus2",
            "ip_address": "203.0.113.25",
            "allocation_method": "Static",
            "sku": "Standard",
            "associated_resource_id": (
                "/subscriptions/test/resourceGroups/network-rg/providers/"
                "Microsoft.Network/loadBalancers/public-lb"
            ),
            "associated_resource_type": "LOAD_BALANCER",
        }
    ]

    result = analyze_public_ip_addresses(public_ip_addresses)

    finding = result["findings"][0]

    assert finding["associated_resource_type"] == "LOAD_BALANCER"
    assert finding["severity"] == "HIGH"
    assert finding["internet_exposed"] is True


def test_returns_empty_public_ip_result():
    result = analyze_public_ip_addresses([])

    assert result == {
        "summary": {
            "public_ip_addresses": 0,
            "assigned_public_ip_addresses": 0,
            "unassigned_public_ip_addresses": 0,
            "high_findings": 0,
            "medium_findings": 0,
        },
        "findings": [],
        "public_ip_addresses": [],
    }


def test_accepts_none_for_public_ip_addresses():
    result = analyze_public_ip_addresses(None)

    assert result["summary"]["public_ip_addresses"] == 0
    assert result["findings"] == []
    assert result["public_ip_addresses"] == []


from azure_network_exposure import analyze_internet_facing_virtual_machines


def test_detects_vm_with_public_ip_and_exposed_ssh():
    virtual_machines = [
        {
            "id": "/subscriptions/test/resourceGroups/prod-rg/providers/"
            "Microsoft.Compute/virtualMachines/linux-vm",
            "name": "linux-vm",
            "resource_group": "prod-rg",
            "location": "eastus",
            "network_interface_ids": [
                "/subscriptions/test/resourceGroups/prod-rg/providers/"
                "Microsoft.Network/networkInterfaces/linux-nic"
            ],
        }
    ]

    network_interfaces = [
        {
            "id": "/subscriptions/test/resourceGroups/prod-rg/providers/"
            "Microsoft.Network/networkInterfaces/linux-nic",
            "name": "linux-nic",
            "public_ip_address_id": (
                "/subscriptions/test/resourceGroups/prod-rg/providers/"
                "Microsoft.Network/publicIPAddresses/linux-public-ip"
            ),
            "network_security_group_id": (
                "/subscriptions/test/resourceGroups/prod-rg/providers/"
                "Microsoft.Network/networkSecurityGroups/linux-nsg"
            ),
        }
    ]

    public_ip_addresses = [
        {
            "id": "/subscriptions/test/resourceGroups/prod-rg/providers/"
            "Microsoft.Network/publicIPAddresses/linux-public-ip",
            "name": "linux-public-ip",
            "ip_address": "203.0.113.40",
        }
    ]

    network_security_groups = [
        {
            "id": "/subscriptions/test/resourceGroups/prod-rg/providers/"
            "Microsoft.Network/networkSecurityGroups/linux-nsg",
            "name": "linux-nsg",
            "security_rules": [
                {
                    "name": "Allow-SSH",
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "22",
                    "protocol": "Tcp",
                    "priority": 100,
                }
            ],
        }
    ]

    result = analyze_internet_facing_virtual_machines(
        virtual_machines=virtual_machines,
        network_interfaces=network_interfaces,
        public_ip_addresses=public_ip_addresses,
        network_security_groups=network_security_groups,
    )

    assert result["summary"]["virtual_machines"] == 1
    assert result["summary"]["internet_facing_virtual_machines"] == 1
    assert result["summary"]["critical_findings"] == 1
    assert result["summary"]["high_findings"] == 0
    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding["resource_name"] == "linux-vm"
    assert finding["public_ip_addresses"] == ["203.0.113.40"]
    assert finding["exposed_ports"] == ["22"]
    assert finding["severity"] == "CRITICAL"
    assert finding["exposure_type"] == "VM_MANAGEMENT_PORT_EXPOSED"
    assert finding["internet_exposed"] is True


def test_detects_vm_with_public_ip_and_exposed_rdp():
    virtual_machines = [
        {
            "name": "windows-vm",
            "network_interface_ids": ["/nics/windows-nic"],
        }
    ]

    network_interfaces = [
        {
            "id": "/nics/windows-nic",
            "public_ip_address_id": "/public-ips/windows-ip",
            "network_security_group_id": "/nsgs/windows-nsg",
        }
    ]

    public_ip_addresses = [
        {
            "id": "/public-ips/windows-ip",
            "ip_address": "198.51.100.50",
        }
    ]

    network_security_groups = [
        {
            "id": "/nsgs/windows-nsg",
            "name": "windows-nsg",
            "security_rules": [
                {
                    "name": "Allow-RDP",
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "0.0.0.0/0",
                    "destination_port_range": "3389",
                }
            ],
        }
    ]

    result = analyze_internet_facing_virtual_machines(
        virtual_machines,
        network_interfaces,
        public_ip_addresses,
        network_security_groups,
    )

    finding = result["findings"][0]

    assert finding["severity"] == "CRITICAL"
    assert finding["exposed_ports"] == ["3389"]
    assert finding["network_security_groups"] == ["windows-nsg"]


def test_detects_public_vm_with_web_port_as_high_severity():
    virtual_machines = [
        {
            "name": "web-vm",
            "network_interface_ids": ["/nics/web-nic"],
        }
    ]

    network_interfaces = [
        {
            "id": "/nics/web-nic",
            "public_ip_address_id": "/public-ips/web-ip",
            "network_security_group_id": "/nsgs/web-nsg",
        }
    ]

    public_ip_addresses = [
        {
            "id": "/public-ips/web-ip",
            "ip_address": "192.0.2.60",
        }
    ]

    network_security_groups = [
        {
            "id": "/nsgs/web-nsg",
            "name": "web-nsg",
            "security_rules": [
                {
                    "name": "Allow-HTTPS",
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "*",
                    "destination_port_range": "443",
                }
            ],
        }
    ]

    result = analyze_internet_facing_virtual_machines(
        virtual_machines,
        network_interfaces,
        public_ip_addresses,
        network_security_groups,
    )

    assert result["summary"]["internet_facing_virtual_machines"] == 1
    assert result["summary"]["critical_findings"] == 0
    assert result["summary"]["high_findings"] == 1

    finding = result["findings"][0]

    assert finding["severity"] == "HIGH"
    assert finding["exposed_ports"] == ["443"]
    assert finding["exposure_type"] == "VM_INTERNET_PORT_EXPOSED"


def test_detects_public_vm_without_network_security_group():
    virtual_machines = [
        {
            "name": "unprotected-vm",
            "network_interface_ids": ["/nics/unprotected-nic"],
        }
    ]

    network_interfaces = [
        {
            "id": "/nics/unprotected-nic",
            "public_ip_address_id": "/public-ips/unprotected-ip",
            "network_security_group_id": None,
        }
    ]

    public_ip_addresses = [
        {
            "id": "/public-ips/unprotected-ip",
            "ip_address": "203.0.113.70",
        }
    ]

    result = analyze_internet_facing_virtual_machines(
        virtual_machines,
        network_interfaces,
        public_ip_addresses,
        [],
    )

    assert result["summary"]["internet_facing_virtual_machines"] == 1
    assert result["summary"]["high_findings"] == 1

    finding = result["findings"][0]

    assert finding["severity"] == "HIGH"
    assert finding["exposure_type"] == "PUBLIC_VM_WITHOUT_NSG"
    assert finding["network_security_groups"] == []
    assert finding["internet_exposed"] is True


def test_ignores_vm_without_public_ip_address():
    virtual_machines = [
        {
            "name": "private-vm",
            "network_interface_ids": ["/nics/private-nic"],
        }
    ]

    network_interfaces = [
        {
            "id": "/nics/private-nic",
            "public_ip_address_id": None,
            "network_security_group_id": "/nsgs/private-nsg",
        }
    ]

    result = analyze_internet_facing_virtual_machines(
        virtual_machines,
        network_interfaces,
        [],
        [],
    )

    assert result["summary"]["virtual_machines"] == 1
    assert result["summary"]["internet_facing_virtual_machines"] == 0
    assert result["summary"]["critical_findings"] == 0
    assert result["summary"]["high_findings"] == 0
    assert result["findings"] == []

    virtual_machine = result["virtual_machines"][0]

    assert virtual_machine["internet_exposed"] is False
    assert virtual_machine["public_ip_addresses"] == []


def test_returns_empty_virtual_machine_exposure_result():
    result = analyze_internet_facing_virtual_machines(
        [],
        [],
        [],
        [],
    )

    assert result == {
        "summary": {
            "virtual_machines": 0,
            "internet_facing_virtual_machines": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
        },
        "findings": [],
        "virtual_machines": [],
    }


def test_accepts_none_for_virtual_machine_exposure_inputs():
    result = analyze_internet_facing_virtual_machines(
        None,
        None,
        None,
        None,
    )

    assert result["summary"]["virtual_machines"] == 0
    assert result["findings"] == []
    assert result["virtual_machines"] == []


from azure_network_exposure import analyze_azure_network_exposure


def test_combines_all_azure_network_exposure_results():
    network_security_groups = [
        {
            "id": "/nsgs/web-nsg",
            "name": "web-nsg",
            "security_rules": [
                {
                    "name": "Allow-SSH",
                    "access": "Allow",
                    "direction": "Inbound",
                    "source_address_prefix": "Internet",
                    "destination_port_range": "22",
                }
            ],
        }
    ]

    public_ip_addresses = [
        {
            "id": "/public-ips/web-ip",
            "name": "web-ip",
            "ip_address": "203.0.113.10",
            "associated_resource_id": "/nics/web-nic",
            "associated_resource_type": "NETWORK_INTERFACE",
        }
    ]

    network_interfaces = [
        {
            "id": "/nics/web-nic",
            "public_ip_address_id": "/public-ips/web-ip",
            "network_security_group_id": "/nsgs/web-nsg",
        }
    ]

    virtual_machines = [
        {
            "id": "/virtual-machines/web-vm",
            "name": "web-vm",
            "network_interface_ids": ["/nics/web-nic"],
        }
    ]

    result = analyze_azure_network_exposure(
        network_security_groups=network_security_groups,
        public_ip_addresses=public_ip_addresses,
        network_interfaces=network_interfaces,
        virtual_machines=virtual_machines,
    )

    assert result["summary"]["network_security_groups"] == 1
    assert result["summary"]["exposed_network_security_groups"] == 1
    assert result["summary"]["public_ip_addresses"] == 1
    assert result["summary"]["assigned_public_ip_addresses"] == 1
    assert result["summary"]["virtual_machines"] == 1
    assert result["summary"]["internet_facing_virtual_machines"] == 1

    assert result["summary"]["critical_findings"] == 2
    assert result["summary"]["high_findings"] == 1
    assert result["summary"]["medium_findings"] == 0
    assert result["summary"]["total_findings"] == 3

    assert len(result["findings"]) == 3
    assert len(result["network_security_groups"]) == 1
    assert len(result["public_ip_addresses"]) == 1
    assert len(result["virtual_machines"]) == 1


def test_returns_empty_unified_network_exposure_result():
    result = analyze_azure_network_exposure(
        network_security_groups=[],
        public_ip_addresses=[],
        network_interfaces=[],
        virtual_machines=[],
    )

    assert result == {
        "summary": {
            "network_security_groups": 0,
            "exposed_network_security_groups": 0,
            "public_ip_addresses": 0,
            "assigned_public_ip_addresses": 0,
            "unassigned_public_ip_addresses": 0,
            "virtual_machines": 0,
            "internet_facing_virtual_machines": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "total_findings": 0,
        },
        "findings": [],
        "network_security_groups": [],
        "public_ip_addresses": [],
        "virtual_machines": [],
    }


def test_unified_network_exposure_accepts_none_inputs():
    result = analyze_azure_network_exposure(
        network_security_groups=None,
        public_ip_addresses=None,
        network_interfaces=None,
        virtual_machines=None,
    )

    assert result["summary"]["total_findings"] == 0
    assert result["findings"] == []
