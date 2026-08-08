import re
from pathlib import Path

import tenant_authorization


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"

FORBIDDEN_GLOBAL_CALLS = (
    "get_all_assets_admin()",
    "get_all_remediation_items_admin()",
    "get_clients()",
)


def _page_blocks():
    text = APP_PATH.read_text()

    pattern = re.compile(
        r'^if page == "([^"]+)":\s*$',
        re.MULTILINE,
    )

    matches = list(
        pattern.finditer(text)
    )

    blocks = {}

    for index, match in enumerate(matches):
        start = match.start()

        if index + 1 < len(matches):
            end = matches[
                index + 1
            ].start()
        else:
            end = len(text)

        blocks[
            match.group(1)
        ] = text[start:end]

    return blocks


def test_all_tenant_safe_pages_exist():
    blocks = _page_blocks()

    missing = (
        set(
            tenant_authorization
            .TENANT_SCOPED_PAGES
        )
        - set(blocks)
    )

    assert not missing, (
        "Tenant-safe pages missing from app.py: "
        f"{sorted(missing)}"
    )


def test_tenant_safe_pages_do_not_use_global_reads():
    blocks = _page_blocks()

    violations = []

    for page in sorted(
        tenant_authorization
        .TENANT_SCOPED_PAGES
    ):
        block = blocks[page]

        for forbidden_call in (
            FORBIDDEN_GLOBAL_CALLS
        ):
            if forbidden_call in block:
                violations.append(
                    (
                        page,
                        forbidden_call,
                    )
                )

    assert not violations, (
        "Tenant-safe pages contain global "
        f"data reads: {violations}"
    )


def test_client_accounts_is_not_tenant_safe():
    assert (
        "Client Accounts"
        not in
        tenant_authorization
        .TENANT_SCOPED_PAGES
    )
