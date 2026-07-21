"""Axonius CAASM connector with secure mock and live modes."""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlparse

import requests

from app_config import is_configured_value, settings


class AxoniusConnectorError(RuntimeError):
    """Raised when Axonius configuration or API delivery fails."""


def normalize_axonius_url(url: str) -> str:
    """Validate and normalize the Axonius base URL."""

    normalized = str(url or "").strip().rstrip("/")

    if not normalized:
        raise AxoniusConnectorError(
            "Axonius base URL is not configured."
        )

    parsed = urlparse(normalized)

    if parsed.scheme != "https" or not parsed.netloc:
        raise AxoniusConnectorError(
            "Axonius base URL must be a valid HTTPS URL."
        )

    if parsed.username or parsed.password:
        raise AxoniusConnectorError(
            "Axonius base URL must not contain embedded credentials."
        )

    return normalized


def axonius_configured() -> bool:
    """Return whether non-placeholder Axonius credentials are configured."""

    return all(
        is_configured_value(value)
        for value in (
            settings.axonius_base_url,
            settings.axonius_api_key,
            settings.axonius_api_secret,
        )
    )


def get_headers(
    api_key: str | None = None,
    api_secret: str | None = None,
) -> dict[str, str]:
    """Build Axonius API headers without exposing credentials."""

    resolved_key = str(
        api_key or settings.axonius_api_key or ""
    ).strip()
    resolved_secret = str(
        api_secret or settings.axonius_api_secret or ""
    ).strip()

    if not (
        is_configured_value(resolved_key)
        and is_configured_value(resolved_secret)
    ):
        raise AxoniusConnectorError(
            "Axonius API credentials are not configured."
        )

    return {
        "api-key": resolved_key,
        "api-secret": resolved_secret,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def get_mock_assets() -> list[dict[str, Any]]:
    return [
        {
            "asset_id": "ax-mock-ec2-001",
            "asset_type": "Cloud Asset",
            "hostname": "prod-app-01",
            "source": "AWS",
            "managed": True,
            "criticality": "HIGH",
            "risk_score": 70,
        },
        {
            "asset_id": "ax-mock-server-002",
            "asset_type": "Server",
            "hostname": "legacy-server-02",
            "source": "Active Directory",
            "managed": False,
            "criticality": "CRITICAL",
            "risk_score": 90,
        },
        {
            "asset_id": "ax-mock-laptop-003",
            "asset_type": "Endpoint",
            "hostname": "finance-laptop-03",
            "source": "Endpoint Security",
            "managed": True,
            "criticality": "MODERATE",
            "risk_score": 45,
        },
    ]


def get_mock_identities() -> list[dict[str, Any]]:
    return [
        {
            "identity_id": "user-001",
            "username": "cloud-admin",
            "identity_type": "Privileged User",
            "privileged": True,
            "mfa_enabled": True,
            "orphaned": False,
            "risk_score": 40,
        },
        {
            "identity_id": "user-002",
            "username": "legacy-service-account",
            "identity_type": "Service Account",
            "privileged": True,
            "mfa_enabled": False,
            "orphaned": True,
            "risk_score": 95,
        },
        {
            "identity_id": "user-003",
            "username": "finance-user",
            "identity_type": "Standard User",
            "privileged": False,
            "mfa_enabled": False,
            "orphaned": False,
            "risk_score": 60,
        },
    ]


def get_mock_coverage_sources() -> list[dict[str, Any]]:
    return [
        {
            "source": "AWS",
            "category": "Cloud",
            "connected": True,
            "assets_discovered": 120,
            "coverage_percent": 95,
        },
        {
            "source": "Active Directory",
            "category": "Identity",
            "connected": True,
            "assets_discovered": 85,
            "coverage_percent": 88,
        },
        {
            "source": "Endpoint Security",
            "category": "Endpoint",
            "connected": True,
            "assets_discovered": 75,
            "coverage_percent": 72,
        },
        {
            "source": "Vulnerability Management",
            "category": "Vulnerability",
            "connected": False,
            "assets_discovered": 0,
            "coverage_percent": 0,
        },
        {
            "source": "Identity Provider",
            "category": "Identity",
            "connected": True,
            "assets_discovered": 90,
            "coverage_percent": 84,
        },
        {
            "source": "MDM",
            "category": "Endpoint",
            "connected": False,
            "assets_discovered": 0,
            "coverage_percent": 0,
        },
        {
            "source": "SIEM",
            "category": "Monitoring",
            "connected": True,
            "assets_discovered": 68,
            "coverage_percent": 65,
        },
    ]


def _extract_records(
    payload: Any,
    record_key: str,
) -> list[dict[str, Any]]:
    """Normalize common Axonius response envelope formats."""

    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        raise AxoniusConnectorError(
            "Axonius returned an unsupported response format."
        )

    for key in (
        record_key,
        "data",
        "results",
        "items",
        "assets",
        "identities",
    ):
        value = payload.get(key)

        if isinstance(value, list):
            return value

    raise AxoniusConnectorError(
        "Axonius response did not contain an asset list."
    )


def _request_records(
    endpoint: str,
    *,
    record_key: str,
    http_get: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """Request and validate a collection from the Axonius API."""

    base_url = normalize_axonius_url(
        settings.axonius_base_url or ""
    )
    timeout = int(settings.axonius_timeout_seconds)

    if timeout <= 0:
        raise AxoniusConnectorError(
            "Axonius timeout must be greater than zero."
        )

    get = http_get or requests.get

    try:
        response = get(
            f"{base_url}{endpoint}",
            headers=get_headers(),
            timeout=timeout,
            verify=settings.axonius_verify_ssl,
        )
    except requests.RequestException as exc:
        raise AxoniusConnectorError(
            "Axonius API request failed."
        ) from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise AxoniusConnectorError(
            "Axonius API rejected the request with "
            f"HTTP status {response.status_code}."
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise AxoniusConnectorError(
            "Axonius returned an invalid JSON response."
        ) from exc

    return _extract_records(payload, record_key)


def test_axonius_connection(
    *,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Validate Axonius API connectivity with a read-only asset request."""

    if not axonius_configured():
        return {
            "status": "NOT_CONFIGURED",
            "mode": "Mock",
            "asset_count": 0,
            "message": "Axonius is not configured.",
        }

    assets = _request_records(
        "/api/assets",
        record_key="assets",
        http_get=http_get,
    )

    return {
        "status": "CONNECTED",
        "mode": "Live",
        "asset_count": len(assets),
        "message": "Axonius API connection succeeded.",
    }


def get_axonius_assets(
    *,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if not axonius_configured():
        return {
            "mode": "Mock",
            "assets": get_mock_assets(),
        }

    return {
        "mode": "Live",
        "assets": _request_records(
            "/api/assets",
            record_key="assets",
            http_get=http_get,
        ),
    }


def get_axonius_identities(
    *,
    http_get: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if not axonius_configured():
        return {
            "mode": "Mock",
            "identities": get_mock_identities(),
        }

    return {
        "mode": "Live",
        "identities": _request_records(
            "/api/identities",
            record_key="identities",
            http_get=http_get,
        ),
    }


def get_axonius_coverage_sources() -> dict[str, Any]:
    return {
        "mode": "Mock",
        "coverage_sources": get_mock_coverage_sources(),
    }
