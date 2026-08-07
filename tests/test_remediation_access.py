import remediation_db


def test_global_admin_receives_all_remediation(
    monkeypatch,
):
    expected = [
        ("item-1",),
        ("item-2",),
    ]

    monkeypatch.setattr(
        remediation_db,
        "get_all_remediation_items_admin",
        lambda: expected,
    )

    monkeypatch.setattr(
        remediation_db,
        "get_remediation_items",
        lambda client_key: [],
    )

    result = (
        remediation_db
        .get_remediation_items_for_access(
            client_keys=["client-a"],
            is_global_admin=True,
        )
    )

    assert result == expected


def test_tenant_user_receives_assigned_remediation(
    monkeypatch,
):
    items_by_client = {
        "client-a": [
            ("item-a1",),
        ],
        "client-b": [
            ("item-b1",),
            ("item-b2",),
        ],
        "client-c": [
            ("item-c1",),
        ],
    }

    requested_keys = []

    def fake_get_items(client_key):
        requested_keys.append(
            client_key
        )
        return items_by_client[
            client_key
        ]

    monkeypatch.setattr(
        remediation_db,
        "get_remediation_items",
        fake_get_items,
    )

    monkeypatch.setattr(
        remediation_db,
        "get_all_remediation_items_admin",
        lambda: [
            ("global-item",)
        ],
    )

    result = (
        remediation_db
        .get_remediation_items_for_access(
            client_keys=[
                "client-b",
                "client-a",
                "client-b",
                "",
                None,
            ],
            is_global_admin=False,
        )
    )

    assert requested_keys == [
        "client-a",
        "client-b",
    ]

    assert result == [
        ("item-a1",),
        ("item-b1",),
        ("item-b2",),
    ]


def test_tenant_user_without_clients_receives_none(
    monkeypatch,
):
    monkeypatch.setattr(
        remediation_db,
        "get_remediation_items",
        lambda client_key: [
            ("unexpected",)
        ],
    )

    result = (
        remediation_db
        .get_remediation_items_for_access(
            client_keys=[],
            is_global_admin=False,
        )
    )

    assert result == []
