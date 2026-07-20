"""Secure Splunk HTTP Event Collector integration."""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

import requests

from app_config import settings


class SplunkHECError(RuntimeError):
    """Raised when Splunk HEC configuration or delivery fails."""


def normalize_hec_url(url: str) -> str:
    """Return a validated Splunk HEC event endpoint."""

    normalized = str(url or "").strip().rstrip("/")

    if not normalized:
        raise SplunkHECError("Splunk HEC URL is not configured.")

    parsed = urlparse(normalized)

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SplunkHECError(
            "Splunk HEC URL must be a valid HTTP or HTTPS URL."
        )

    if parsed.username or parsed.password:
        raise SplunkHECError(
            "Splunk HEC URL must not contain embedded credentials."
        )

    if normalized.endswith("/services/collector/event"):
        return normalized

    if normalized.endswith("/services/collector"):
        return f"{normalized}/event"

    return f"{normalized}/services/collector/event"


def build_hec_payload(
    event: Any,
    *,
    index: str,
    source: str,
    sourcetype: str,
    host: str | None = None,
    event_time: float | None = None,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Splunk HEC event envelope."""

    payload: dict[str, Any] = {
        "time": (
            float(event_time)
            if event_time is not None
            else time.time()
        ),
        "index": str(index).strip() or "main",
        "source": str(source).strip() or "dgs_sentinel_ai",
        "sourcetype": str(sourcetype).strip() or "_json",
        "event": event,
    }

    if host:
        payload["host"] = str(host).strip()

    if fields:
        payload["fields"] = dict(fields)

    return payload


def send_event(
    event: Any,
    *,
    hec_url: str | None = None,
    token: str | None = None,
    index: str | None = None,
    source: str | None = None,
    sourcetype: str | None = None,
    host: str | None = None,
    event_time: float | None = None,
    fields: dict[str, Any] | None = None,
    verify_ssl: bool | None = None,
    timeout_seconds: int | None = None,
    http_post: Any = None,
) -> dict[str, Any]:
    """Send one event to Splunk HEC and verify acceptance."""

    resolved_url = normalize_hec_url(
        hec_url or settings.splunk_hec_url or ""
    )
    resolved_token = str(
        token or settings.splunk_hec_token or ""
    ).strip()

    if not resolved_token:
        raise SplunkHECError("Splunk HEC token is not configured.")

    resolved_index = index or settings.splunk_index
    resolved_source = source or settings.splunk_source
    resolved_sourcetype = (
        sourcetype or settings.splunk_sourcetype
    )
    resolved_verify_ssl = (
        settings.splunk_verify_ssl
        if verify_ssl is None
        else bool(verify_ssl)
    )
    resolved_timeout = (
        settings.splunk_timeout_seconds
        if timeout_seconds is None
        else int(timeout_seconds)
    )

    if resolved_timeout <= 0:
        raise SplunkHECError(
            "Splunk HEC timeout must be greater than zero."
        )

    payload = build_hec_payload(
        event,
        index=resolved_index,
        source=resolved_source,
        sourcetype=resolved_sourcetype,
        host=host,
        event_time=event_time,
        fields=fields,
    )

    post = http_post or requests.post

    try:
        response = post(
            resolved_url,
            headers={
                "Authorization": f"Splunk {resolved_token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=resolved_timeout,
            verify=resolved_verify_ssl,
        )
    except requests.RequestException as exc:
        raise SplunkHECError(
            "Splunk HEC request failed."
        ) from exc

    if response.status_code < 200 or response.status_code >= 300:
        raise SplunkHECError(
            "Splunk HEC rejected the event with "
            f"HTTP status {response.status_code}."
        )

    try:
        response_body = response.json()
    except ValueError as exc:
        raise SplunkHECError(
            "Splunk HEC returned an invalid JSON response."
        ) from exc

    if response_body.get("code") != 0:
        response_text = str(
            response_body.get("text", "Unknown Splunk HEC error")
        )
        raise SplunkHECError(
            f"Splunk HEC rejected the event: {response_text}"
        )

    return {
        "status": "SENT",
        "http_status": response.status_code,
        "splunk_code": response_body.get("code"),
        "splunk_text": response_body.get("text"),
        "endpoint": resolved_url,
        "index": payload["index"],
        "source": payload["source"],
        "sourcetype": payload["sourcetype"],
    }
