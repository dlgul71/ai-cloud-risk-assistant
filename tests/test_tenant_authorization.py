import tenant_authorization


def test_global_admin_session_has_global_access():
    session = {
        "authenticated_is_global_admin": True,
        "authenticated_client_keys": [],
    }

    assert (
        tenant_authorization
        .authenticated_is_global_admin(
            session
        )
    )
    assert tenant_authorization.can_access_client(
        session,
        "any-client",
    )
    assert tenant_authorization.require_global_admin(
        session
    )


def test_tenant_user_access_is_limited_to_assignments():
    session = {
        "authenticated_is_global_admin": False,
        "authenticated_client_keys": [
            "client-a",
            "client-b",
        ],
    }

    assert tenant_authorization.can_access_client(
        session,
        "client-a",
    )
    assert not tenant_authorization.can_access_client(
        session,
        "client-c",
    )
    assert not tenant_authorization.require_global_admin(
        session
    )


def test_client_keys_are_normalized_and_deduplicated():
    session = {
        "authenticated_client_keys": [
            "client-b",
            " client-a ",
            "client-b",
            "",
            None,
        ]
    }

    assert (
        tenant_authorization
        .authenticated_client_keys(
            session
        )
        == (
            "client-a",
            "client-b",
        )
    )


def test_blank_client_key_is_never_authorized():
    session = {
        "authenticated_is_global_admin": True
    }

    assert not tenant_authorization.can_access_client(
        session,
        ""
    )
    assert not tenant_authorization.can_access_client(
        session,
        None,
    )


def test_string_client_key_session_value_is_supported():
    session = {
        "authenticated_client_keys": (
            "client-a"
        )
    }

    assert (
        tenant_authorization
        .authenticated_client_keys(
            session
        )
        == ("client-a",)
    )


def test_global_admin_keeps_all_navigation_pages():
    session = {
        "authenticated_is_global_admin": True
    }
    pages = [
        "Dashboard",
        "Executive Dashboard",
        "Client Security Dashboard",
        "System Health",
    ]

    assert (
        tenant_authorization
        .filter_navigation_pages(
            session,
            pages,
        )
        == pages
    )


def test_tenant_user_receives_only_tenant_safe_pages():
    session = {
        "authenticated_is_global_admin": False,
        "authenticated_client_keys": [
            "client-a"
        ],
    }
    pages = [
        "Dashboard",
        "Executive Dashboard",
        "Client Security Dashboard",
        "SOC Dashboard",
        "Asset Dashboard",
        "Client Accounts",
        "System Health",
    ]

    assert (
        tenant_authorization
        .filter_navigation_pages(
            session,
            pages,
        )
        == [
            "Executive Dashboard",
            "Client Security Dashboard",
            "SOC Dashboard",
            "Asset Dashboard",
        ]
    )
