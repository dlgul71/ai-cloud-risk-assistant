"""Authenticated tenant-boundary helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def authenticated_is_global_admin(
    session: Mapping[str, Any],
) -> bool:
    return bool(
        session.get(
            "authenticated_is_global_admin",
            False,
        )
    )


def authenticated_client_keys(
    session: Mapping[str, Any],
) -> tuple[str, ...]:
    raw_keys = session.get(
        "authenticated_client_keys",
        [],
    )

    if isinstance(raw_keys, str):
        raw_keys = [raw_keys]

    return tuple(
        sorted(
            {
                str(client_key or "").strip()
                for client_key in (
                    raw_keys or []
                )
                if str(
                    client_key or ""
                ).strip()
            }
        )
    )


def can_access_client(
    session: Mapping[str, Any],
    client_key: str | None,
) -> bool:
    normalized_client_key = str(
        client_key or ""
    ).strip()

    if not normalized_client_key:
        return False

    if authenticated_is_global_admin(
        session
    ):
        return True

    return normalized_client_key in set(
        authenticated_client_keys(
            session
        )
    )


def require_global_admin(
    session: Mapping[str, Any],
) -> bool:
    """
    Return whether the authenticated identity may use global views.

    This is intentionally separate from the RBAC role. An
    Administrator role without is_global_admin remains tenant-scoped.
    """

    return authenticated_is_global_admin(
        session
    )


TENANT_SCOPED_PAGES = frozenset(
    {
        "Client Security Dashboard",
    }
)


def filter_navigation_pages(
    session: Mapping[str, Any],
    pages: list[str] | tuple[str, ...],
) -> list[str]:
    """
    Restrict non-global users to pages already proven tenant-safe.

    Additional pages can be added only after every data query on the
    page has been tenant-scoped.
    """

    if authenticated_is_global_admin(
        session
    ):
        return list(pages)

    return [
        page
        for page in pages
        if page in TENANT_SCOPED_PAGES
    ]
