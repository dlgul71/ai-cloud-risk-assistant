import sentinel_ai_analyst


def _asset_row(asset_id, account_id, risk_score=50):
    return (
        asset_id,
        "EC2",
        account_id,
        "us-east-1",
        f"{asset_id}.example",
        "10.0.0.10",
        None,
        "running",
        risk_score,
        "2026-08-09T00:00:00Z",
    )


def _remediation_row(item_id, finding, risk_score=70):
    return (
        item_id,
        "2026-08-09T00:00:00Z",
        "Cloud Security",
        "HIGH",
        finding,
        "Remediate the finding.",
        "Security",
        "Open",
        risk_score,
        1,
        "2026-08-09T00:00:00Z",
    )


def _remediation_context_row(
    item_id,
    finding,
    account_id,
    client_name,
    risk_score=70,
):
    return (
        item_id,
        "2026-08-09T00:00:00Z",
        "Cloud Security",
        "HIGH",
        finding,
        "Remediate the finding.",
        "Security",
        "Open",
        risk_score,
        1,
        "2026-08-09T00:00:00Z",
        account_id,
        client_name,
    )


def test_tenant_security_context_uses_only_authorized_access(monkeypatch):
    calls = {
        "assets": None,
        "remediation": None,
        "context_keys": [],
    }

    def fake_assets_for_access(*, client_keys=None, is_global_admin=False):
        calls["assets"] = (tuple(client_keys or ()), is_global_admin)
        return [_asset_row("asset-a", "111111111111")]

    def fake_remediation_for_access(*, client_keys=None, is_global_admin=False):
        calls["remediation"] = (tuple(client_keys or ()), is_global_admin)
        return [_remediation_row(1, "Tenant A finding")]

    def fake_context(client_key):
        calls["context_keys"].append(client_key)
        return [
            _remediation_context_row(
                1,
                "Tenant A finding",
                "111111111111",
                "Tenant A",
            )
        ]

    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_assets_for_access",
        fake_assets_for_access,
    )
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_remediation_items_for_access",
        fake_remediation_for_access,
    )
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_remediation_items_with_client_context",
        fake_context,
    )

    context = sentinel_ai_analyst.build_security_context_for_access(
        client_keys=[" tenant-a ", "tenant-a", ""],
        is_global_admin=False,
    )

    assert calls["assets"] == (("tenant-a",), False)
    assert calls["remediation"] == (("tenant-a",), False)
    assert calls["context_keys"] == ["tenant-a"]

    assert [item["asset_id"] for item in context["assets"]] == [
        "asset-a"
    ]
    assert [
        item["finding"]
        for item in context["remediation_items"]
    ] == ["Tenant A finding"]
    assert context["remediation_items_with_context"][0][
        "client_name"
    ] == "Tenant A"


def test_tenant_security_context_fails_closed_for_unscoped_sources(
    monkeypatch,
):
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_assets_for_access",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_remediation_items_for_access",
        lambda **kwargs: [],
    )
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_remediation_items_with_client_context",
        lambda client_key: [],
    )

    context = sentinel_ai_analyst.build_security_context_for_access(
        client_keys=["tenant-a"],
        is_global_admin=False,
    )

    assert context["execution_actions"] == []
    assert context["latest_caasm_snapshot"] == {}
    assert context["caasm_snapshot_count"] == 0


def test_no_client_assignment_returns_no_tenant_data(monkeypatch):
    observed = {
        "asset_keys": None,
        "remediation_keys": None,
    }

    def fake_assets_for_access(*, client_keys=None, is_global_admin=False):
        observed["asset_keys"] = tuple(client_keys or ())
        return []

    def fake_remediation_for_access(
        *,
        client_keys=None,
        is_global_admin=False,
    ):
        observed["remediation_keys"] = tuple(client_keys or ())
        return []

    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_assets_for_access",
        fake_assets_for_access,
    )
    monkeypatch.setattr(
        sentinel_ai_analyst,
        "get_remediation_items_for_access",
        fake_remediation_for_access,
    )

    context = sentinel_ai_analyst.build_security_context_for_access(
        client_keys=[],
        is_global_admin=False,
    )

    assert observed["asset_keys"] == ()
    assert observed["remediation_keys"] == ()
    assert context["assets"] == []
    assert context["remediation_items"] == []
    assert context["remediation_items_with_context"] == []


def test_global_admin_preserves_existing_global_context(monkeypatch):
    expected = {
        "assets": [{"asset_id": "global-asset"}],
        "remediation_items": [],
        "remediation_items_with_context": [],
        "execution_actions": [{"id": 1}],
        "latest_caasm_snapshot": {
            "metrics": {
                "CAASM Score": 90
            }
        },
        "caasm_snapshot_count": 3,
    }

    monkeypatch.setattr(
        sentinel_ai_analyst,
        "build_security_context",
        lambda: expected,
    )

    context = sentinel_ai_analyst.build_security_context_for_access(
        client_keys=["tenant-a"],
        is_global_admin=True,
    )

    assert context is expected
