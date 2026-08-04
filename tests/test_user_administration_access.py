import access_control


def test_administrator_can_manage_users():
    assert access_control.has_permission(
        access_control.ROLE_ADMINISTRATOR,
        access_control.PERMISSION_MANAGE_USERS,
    )


def test_analyst_cannot_manage_users():
    assert not access_control.has_permission(
        access_control.ROLE_ANALYST,
        access_control.PERMISSION_MANAGE_USERS,
    )


def test_viewer_cannot_manage_users():
    assert not access_control.has_permission(
        access_control.ROLE_VIEWER,
        access_control.PERMISSION_MANAGE_USERS,
    )


def test_user_administration_page_requires_permission():
    assert access_control.can_access_page(
        access_control.ROLE_ADMINISTRATOR,
        "User Administration",
    )

    assert not access_control.can_access_page(
        access_control.ROLE_ANALYST,
        "User Administration",
    )

    assert not access_control.can_access_page(
        access_control.ROLE_VIEWER,
        "User Administration",
    )
