import asset_db


def test_global_admin_receives_all_assets(
    monkeypatch,
):
    expected_assets = [
        ("asset-1",),
        ("asset-2",),
    ]

    monkeypatch.setattr(
        asset_db,
        "get_all_assets_admin",
        lambda: expected_assets,
    )

    monkeypatch.setattr(
        asset_db,
        "get_assets",
        lambda client_key: [],
    )

    result = asset_db.get_assets_for_access(
        client_keys=["client-a"],
        is_global_admin=True,
    )

    assert result == expected_assets


def test_tenant_user_receives_only_assigned_assets(
    monkeypatch,
):
    assets_by_client = {
        "client-a": [
            ("asset-a1",),
        ],
        "client-b": [
            ("asset-b1",),
            ("asset-b2",),
        ],
        "client-c": [
            ("asset-c1",),
        ],
    }

    requested_client_keys = []

    def fake_get_assets(client_key):
        requested_client_keys.append(
            client_key
        )
        return assets_by_client[
            client_key
        ]

    monkeypatch.setattr(
        asset_db,
        "get_assets",
        fake_get_assets,
    )

    monkeypatch.setattr(
        asset_db,
        "get_all_assets_admin",
        lambda: [
            ("global-asset",),
        ],
    )

    result = asset_db.get_assets_for_access(
        client_keys=[
            "client-b",
            "client-a",
            "client-b",
            "",
            None,
        ],
        is_global_admin=False,
    )

    assert requested_client_keys == [
        "client-a",
        "client-b",
    ]

    assert result == [
        ("asset-a1",),
        ("asset-b1",),
        ("asset-b2",),
    ]


def test_tenant_user_without_assignments_receives_no_assets(
    monkeypatch,
):
    monkeypatch.setattr(
        asset_db,
        "get_assets",
        lambda client_key: [
            ("unexpected",)
        ],
    )

    result = asset_db.get_assets_for_access(
        client_keys=[],
        is_global_admin=False,
    )

    assert result == []
