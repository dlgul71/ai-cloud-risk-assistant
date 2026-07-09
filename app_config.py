"""Centralized application configuration.

Precedence:
1. Operating-system environment variables
2. Streamlit secrets
3. Supplied default values

The local .env file is loaded without overriding existing environment
variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from dotenv import load_dotenv


load_dotenv(override=False)


def _streamlit_secret(key: str) -> Any:
    try:
        import streamlit as st

        value: Any = st.secrets

        for part in key.split("."):
            value = value[part]

        return value

    except Exception:
        return None


def get_setting(
    key: str,
    default: Any = None,
    required: bool = False,
) -> Any:
    environment_value = os.getenv(key)

    if environment_value not in {None, ""}:
        return environment_value

    secret_value = _streamlit_secret(key)

    if secret_value not in {None, ""}:
        return secret_value

    if required and default is None:
        raise RuntimeError(
            f"Required configuration setting is missing: {key}"
        )

    return default


def get_first_setting(
    *keys: str,
    default: Any = None,
    required: bool = False,
) -> Any:
    for key in keys:
        value = get_setting(key)

        if value not in {None, ""}:
            return value

    if required and default is None:
        joined_keys = ", ".join(keys)

        raise RuntimeError(
            "Required configuration setting is missing. "
            f"Checked: {joined_keys}"
        )

    return default


def get_bool(
    key: str,
    default: bool = False,
) -> bool:
    value = get_setting(key, default)

    if isinstance(value, bool):
        return value

    return str(value).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def get_int(
    key: str,
    default: int,
) -> int:
    value = get_setting(key, default)

    try:
        return int(value)

    except (TypeError, ValueError):
        return default


def get_csv(
    key: str,
) -> tuple[str, ...]:
    value = get_setting(key)

    if value in {None, ""}:
        return ()

    return tuple(
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    )


@dataclass(frozen=True)
class AppSettings:
    app_name: str = "DGS Sentinel AI"
    app_env: str = field(
        default_factory=lambda: str(
            get_setting("APP_ENV", "development")
        )
    )
    log_level: str = field(
        default_factory=lambda: str(
            get_setting("LOG_LEVEL", "INFO")
        ).upper()
    )
    aws_region: str = field(
        default_factory=lambda: str(
            get_setting("AWS_REGION", "us-east-1")
        )
    )
    public_demo_mode: bool = field(
        default_factory=lambda: get_bool(
            "DGS_PUBLIC_DEMO_MODE",
            False,
        )
    )
    live_remediation_enabled: bool = field(
        default_factory=lambda: get_bool(
            "DGS_LIVE_REMEDIATION_ENABLED",
            False,
        )
    )
    session_timeout_minutes: int = field(
        default_factory=lambda: get_int(
            "SESSION_TIMEOUT_MINUTES",
            30,
        )
    )

    openai_api_key: str | None = field(
        default_factory=lambda: get_setting(
            "OPENAI_API_KEY"
        ),
        repr=False,
    )
    app_username: str | None = field(
        default_factory=lambda: get_first_setting(
            "APP_USERNAME",
            "auth.username",
        ),
        repr=False,
    )
    app_password: str | None = field(
        default_factory=lambda: get_first_setting(
            "APP_PASSWORD",
            "auth.password",
        ),
        repr=False,
    )
    app_role: str = field(
        default_factory=lambda: str(
            get_first_setting(
                "DGS_APP_ROLE",
                "auth.role",
                default="Administrator",
            )
        )
    )
    remediation_evidence_hmac_key: str | None = field(
        default_factory=lambda: get_setting(
            "DGS_REMEDIATION_EVIDENCE_HMAC_KEY"
        ),
        repr=False,
    )
    remediation_evidence_previous_hmac_keys: tuple[str, ...] = field(
        default_factory=lambda: get_csv(
            "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS"
        ),
        repr=False,
    )

    def safe_summary(self) -> dict[str, Any]:
        return {
            "app_name": self.app_name,
            "app_env": self.app_env,
            "log_level": self.log_level,
            "aws_region": self.aws_region,
            "public_demo_mode": self.public_demo_mode,
            "live_remediation_enabled": (
                self.live_remediation_enabled
            ),
            "session_timeout_minutes": (
                self.session_timeout_minutes
            ),
            "openai_configured": bool(
                self.openai_api_key
            ),
            "app_credentials_configured": bool(
                self.app_username
                and self.app_password
            ),
            "app_role": self.app_role,
            "remediation_evidence_hmac_configured": bool(
                self.remediation_evidence_hmac_key
            ),
            "remediation_evidence_previous_key_count": len(
                self.remediation_evidence_previous_hmac_keys
            ),
        }


settings = AppSettings()
