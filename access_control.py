"""Role-based access control for DGS Sentinel AI."""

from __future__ import annotations

ROLE_ADMINISTRATOR = "Administrator"
ROLE_ANALYST = "Analyst"
ROLE_VIEWER = "Viewer"

VALID_ROLES = (
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    ROLE_VIEWER,
)

PERMISSION_VIEW_DASHBOARDS = "view_dashboards"
PERMISSION_RUN_SCANS = "run_scans"
PERMISSION_MANAGE_CLIENTS = "manage_clients"
PERMISSION_APPROVE_REMEDIATION = "approve_remediation"
PERMISSION_EXECUTE_REMEDIATION = "execute_remediation"
PERMISSION_VIEW_EXECUTION_EVIDENCE = "view_execution_evidence"
PERMISSION_VIEW_SYSTEM_HEALTH = "view_system_health"
PERMISSION_MANAGE_USERS = "manage_users"

ROLE_PERMISSIONS = {
    ROLE_ADMINISTRATOR: {
        PERMISSION_VIEW_DASHBOARDS,
        PERMISSION_RUN_SCANS,
        PERMISSION_MANAGE_CLIENTS,
        PERMISSION_APPROVE_REMEDIATION,
        PERMISSION_EXECUTE_REMEDIATION,
        PERMISSION_VIEW_EXECUTION_EVIDENCE,
        PERMISSION_VIEW_SYSTEM_HEALTH,
        PERMISSION_MANAGE_USERS,
    },
    ROLE_ANALYST: {
        PERMISSION_VIEW_DASHBOARDS,
        PERMISSION_RUN_SCANS,
        PERMISSION_VIEW_EXECUTION_EVIDENCE,
    },
    ROLE_VIEWER: {
        PERMISSION_VIEW_DASHBOARDS,
    },
}

PAGE_PERMISSIONS = {
    "Client Accounts": PERMISSION_MANAGE_CLIENTS,
    "User Administration": PERMISSION_MANAGE_USERS,
    "Execution Center": PERMISSION_VIEW_EXECUTION_EVIDENCE,
    "System Health": PERMISSION_VIEW_SYSTEM_HEALTH,
}


def normalize_role(role: str | None) -> str:
    candidate = str(role or "").strip().lower()

    for valid_role in VALID_ROLES:
        if candidate == valid_role.lower():
            return valid_role

    return ROLE_VIEWER


def has_permission(
    role: str | None,
    permission: str,
) -> bool:
    normalized_role = normalize_role(role)

    return permission in ROLE_PERMISSIONS[normalized_role]


def can_access_page(
    role: str | None,
    page: str,
) -> bool:
    required_permission = PAGE_PERMISSIONS.get(
        page,
        PERMISSION_VIEW_DASHBOARDS,
    )

    return has_permission(
        role,
        required_permission,
    )


def accessible_pages(
    role: str | None,
    pages: list[str] | tuple[str, ...],
) -> list[str]:
    return [
        page
        for page in pages
        if can_access_page(role, page)
    ]
