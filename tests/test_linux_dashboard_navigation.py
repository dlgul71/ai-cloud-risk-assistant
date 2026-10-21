import pytest

from access_control import accessible_pages
from tenant_authorization import (
    can_access_client,
    filter_navigation_pages,
)

PAGE = "Linux Security Monitoring"


@pytest.mark.parametrize(
    "role",
    ["Administrator", "Analyst", "Viewer"],
)
def test_dashboard_role_visibility(role):
    pages = accessible_pages(role, [PAGE])
    assert PAGE in pages


def test_assigned_client_navigation():
    session = {
        "authenticated_is_global_admin": False,
        "authenticated_client_keys": ["client-A"],
    }

    pages = filter_navigation_pages(session, [PAGE])

    assert PAGE in pages
    assert can_access_client(session, "client-A")
    assert not can_access_client(session, "client-B")


def test_global_admin_navigation():
    session = {
        "authenticated_is_global_admin": True,
    }

    pages = filter_navigation_pages(session, [PAGE])

    assert PAGE in pages
    assert can_access_client(session, "client-B")


def test_unassigned_client_access_denied():
    session = {
        "authenticated_is_global_admin": False,
        "authenticated_client_keys": [],
    }

    assert not can_access_client(session, "client-A")
