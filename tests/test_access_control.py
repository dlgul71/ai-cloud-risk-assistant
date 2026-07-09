import access_control


def test_normalize_role_accepts_configured_roles():
    assert access_control.normalize_role("administrator") == "Administrator"
    assert access_control.normalize_role("ANALYST") == "Analyst"
    assert access_control.normalize_role(" Viewer ") == "Viewer"


def test_normalize_role_defaults_unknown_role_to_viewer():
    assert access_control.normalize_role("Unknown") == "Viewer"
    assert access_control.normalize_role(None) == "Viewer"


def test_administrator_has_all_permissions():
    for permission in access_control.ROLE_PERMISSIONS[
        access_control.ROLE_ADMINISTRATOR
    ]:
        assert access_control.has_permission(
            access_control.ROLE_ADMINISTRATOR,
            permission,
        )


def test_analyst_cannot_manage_clients_or_execute_remediation():
    assert access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_RUN_SCANS,
    )
    assert not access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_MANAGE_CLIENTS,
    )
    assert not access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_EXECUTE_REMEDIATION,
    )


def test_viewer_can_only_access_dashboard_pages():
    assert access_control.can_access_page(
        access_control.ROLE_VIEWER,
        "Dashboard",
    )
    assert not access_control.can_access_page(
        access_control.ROLE_VIEWER,
        "Execution Center",
    )
    assert not access_control.can_access_page(
        access_control.ROLE_VIEWER,
        "System Health",
    )


def test_accessible_pages_filters_restricted_pages():
    pages = [
        "Dashboard",
        "Execution Center",
        "Client Accounts",
        "System Health",
    ]

    assert access_control.accessible_pages(
        access_control.ROLE_ANALYST,
        pages,
    ) == [
        "Dashboard",
        "Execution Center",
    ]


def test_administrator_can_manage_remediation_actions():
    assert access_control.has_permission(
        access_control.ROLE_ADMINISTRATOR,
        access_control.PERMISSION_APPROVE_REMEDIATION,
    )
    assert access_control.has_permission(
        access_control.ROLE_ADMINISTRATOR,
        access_control.PERMISSION_EXECUTE_REMEDIATION,
    )


def test_analyst_has_scan_and_evidence_access_only():
    assert access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_RUN_SCANS,
    )
    assert access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_VIEW_EXECUTION_EVIDENCE,
    )
    assert not access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_APPROVE_REMEDIATION,
    )


def test_viewer_cannot_run_scans_or_modify_platform_data():
    assert not access_control.has_permission(
        access_control.ROLE_VIEWER,
        access_control.PERMISSION_RUN_SCANS,
    )
    assert not access_control.has_permission(
        access_control.ROLE_VIEWER,
        access_control.PERMISSION_MANAGE_CLIENTS,
    )
    assert not access_control.has_permission(
        access_control.ROLE_VIEWER,
        access_control.PERMISSION_APPROVE_REMEDIATION,
    )
    assert not access_control.has_permission(
        access_control.ROLE_VIEWER,
        access_control.PERMISSION_EXECUTE_REMEDIATION,
    )
