import os
import requests


AXONIUS_BASE_URL = os.getenv("AXONIUS_BASE_URL", "")
AXONIUS_API_KEY = os.getenv("AXONIUS_API_KEY", "")
AXONIUS_API_SECRET = os.getenv("AXONIUS_API_SECRET", "")


def axonius_configured():
    return all([
        AXONIUS_BASE_URL,
        AXONIUS_API_KEY,
        AXONIUS_API_SECRET
    ])


def get_headers():
    return {
        "api-key": AXONIUS_API_KEY,
        "api-secret": AXONIUS_API_SECRET,
        "Content-Type": "application/json"
    }


def get_mock_assets():
    return [
        {
            "asset_id": "ax-mock-ec2-001",
            "asset_type": "Cloud Asset",
            "hostname": "prod-app-01",
            "source": "AWS",
            "managed": True,
            "criticality": "HIGH",
            "risk_score": 70
        },
        {
            "asset_id": "ax-mock-server-002",
            "asset_type": "Server",
            "hostname": "legacy-server-02",
            "source": "Active Directory",
            "managed": False,
            "criticality": "CRITICAL",
            "risk_score": 90
        },
        {
            "asset_id": "ax-mock-laptop-003",
            "asset_type": "Endpoint",
            "hostname": "finance-laptop-03",
            "source": "Endpoint Security",
            "managed": True,
            "criticality": "MODERATE",
            "risk_score": 45
        }
    ]


def get_mock_identities():
    return [
        {
            "identity_id": "user-001",
            "username": "cloud-admin",
            "identity_type": "Privileged User",
            "privileged": True,
            "mfa_enabled": True,
            "orphaned": False,
            "risk_score": 40
        },
        {
            "identity_id": "user-002",
            "username": "legacy-service-account",
            "identity_type": "Service Account",
            "privileged": True,
            "mfa_enabled": False,
            "orphaned": True,
            "risk_score": 95
        },
        {
            "identity_id": "user-003",
            "username": "finance-user",
            "identity_type": "Standard User",
            "privileged": False,
            "mfa_enabled": False,
            "orphaned": False,
            "risk_score": 60
        }
    ]


def get_axonius_assets():
    if not axonius_configured():
        return {
            "mode": "Mock",
            "assets": get_mock_assets()
        }

    response = requests.get(
        f"{AXONIUS_BASE_URL.rstrip('/')}/api/assets",
        headers=get_headers(),
        timeout=30
    )

    response.raise_for_status()

    return {
        "mode": "Live",
        "assets": response.json()
    }


def get_axonius_identities():
    if not axonius_configured():
        return {
            "mode": "Mock",
            "identities": get_mock_identities()
        }

    response = requests.get(
        f"{AXONIUS_BASE_URL.rstrip('/')}/api/identities",
        headers=get_headers(),
        timeout=30
    )

    response.raise_for_status()

    return {
        "mode": "Live",
        "identities": response.json()
    }


def get_mock_coverage_sources():
    return [
        {
            "source": "AWS",
            "category": "Cloud",
            "connected": True,
            "assets_discovered": 120,
            "coverage_percent": 95
        },
        {
            "source": "Active Directory",
            "category": "Identity",
            "connected": True,
            "assets_discovered": 85,
            "coverage_percent": 88
        },
        {
            "source": "Endpoint Security",
            "category": "Endpoint",
            "connected": True,
            "assets_discovered": 75,
            "coverage_percent": 72
        },
        {
            "source": "Vulnerability Management",
            "category": "Vulnerability",
            "connected": False,
            "assets_discovered": 0,
            "coverage_percent": 0
        },
        {
            "source": "Identity Provider",
            "category": "Identity",
            "connected": True,
            "assets_discovered": 90,
            "coverage_percent": 84
        },
        {
            "source": "MDM",
            "category": "Endpoint",
            "connected": False,
            "assets_discovered": 0,
            "coverage_percent": 0
        },
        {
            "source": "SIEM",
            "category": "Monitoring",
            "connected": True,
            "assets_discovered": 68,
            "coverage_percent": 65
        }
    ]


def get_axonius_coverage_sources():
    return {
        "mode": "Mock",
        "coverage_sources": get_mock_coverage_sources()
    }
