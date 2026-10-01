"""Centralized runtime storage paths for DGS Sentinel AI."""

from __future__ import annotations

import os
from pathlib import Path


DATA_DIRECTORY_ENV = "DGS_DATA_DIR"

# Shared default inventory for SQLite backup and health checks.
SQLITE_DATABASE_NAMES = (
    "assets.db",
    "clients.db",
    "remediation.db",
    "operational_monitoring.db",
    "users.db",
    "ai_assets.db",
    "caasm_alerts.db",
    "dgs_sentinel.db",
    "remediation_actions.db",
)


def get_data_directory() -> Path:
    """Return the configured persistent runtime data directory."""

    configured_value = os.getenv(
        DATA_DIRECTORY_ENV,
        "",
    ).strip()

    if not configured_value:
        return Path(".")

    return Path(configured_value).expanduser()


def _safe_child_name(name: str) -> str:
    """Validate a single file or directory name."""

    candidate = Path(str(name))

    if (
        candidate.is_absolute()
        or candidate.name != str(name)
        or len(candidate.parts) != 1
        or str(name) in {"", ".", ".."}
    ):
        raise ValueError(
            "Runtime storage names must be simple "
            "file or directory names."
        )

    return str(name)


def database_path(
    database_name: str,
) -> Path:
    """Return a database path inside the configured data directory."""

    safe_name = _safe_child_name(
        database_name
    )

    return get_data_directory() / safe_name


def runtime_directory(
    directory_name: str,
) -> Path:
    """Return and create a runtime directory under the data directory."""

    safe_name = _safe_child_name(
        directory_name
    )

    directory = (
        get_data_directory() / safe_name
    )
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def default_database_paths() -> tuple[Path, ...]:
    """Resolve the default SQLite inventory without creating files."""

    return tuple(database_path(name) for name in SQLITE_DATABASE_NAMES)
