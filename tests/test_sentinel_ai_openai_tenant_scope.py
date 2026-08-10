import sentinel_ai_openai


def test_payload_uses_tenant_scoped_context(monkeypatch):
    observed = {}

    def fake_context(*, client_keys=None, is_global_admin=False):
        observed["client_keys"] = tuple(client_keys or ())
        observed["is_global_admin"] = is_global_admin
        return {
            "assets": [],
            "remediation_items": [],
            "remediation_items_with_context": [],
            "execution_actions": [],
            "latest_caasm_snapshot": {},
            "caasm_snapshot_count": 0,
        }

    monkeypatch.setattr(
        sentinel_ai_openai,
        "build_security_context_for_access",
        fake_context,
    )

    payload = sentinel_ai_openai.build_grounded_narrative_payload(
        client_keys=["tenant-a"],
        is_global_admin=False,
    )

    assert observed["client_keys"] == ("tenant-a",)
    assert observed["is_global_admin"] is False
    assert payload["tenant_scope"]["is_global_admin"] is False
    assert payload["tenant_scope"]["client_keys"] == ["tenant-a"]


def test_tenant_payload_excludes_global_caasm_comparison(monkeypatch):
    monkeypatch.setattr(
        sentinel_ai_openai,
        "build_security_context_for_access",
        lambda **kwargs: {
            "assets": [],
            "remediation_items": [],
            "remediation_items_with_context": [],
            "execution_actions": [],
            "latest_caasm_snapshot": {},
            "caasm_snapshot_count": 0,
        },
    )

    payload = sentinel_ai_openai.build_grounded_narrative_payload(
        client_keys=["tenant-a"],
        is_global_admin=False,
    )

    comparison = payload["caasm_snapshot_comparison"]

    assert comparison["available"] is False
    assert "tenant boundary" in comparison["message"]


def test_global_admin_can_use_global_caasm_comparison(monkeypatch):
    monkeypatch.setattr(
        sentinel_ai_openai,
        "build_security_context_for_access",
        lambda **kwargs: {
            "assets": [],
            "remediation_items": [],
            "remediation_items_with_context": [],
            "execution_actions": [],
            "latest_caasm_snapshot": {},
            "caasm_snapshot_count": 2,
        },
    )

    expected = {
        "available": True,
        "comparison": {
            "CAASM Score Change": 5
        },
    }

    import sentinel_ai_analyst

    monkeypatch.setattr(
        sentinel_ai_analyst,
        "compare_latest_caasm_snapshots",
        lambda: expected,
    )

    payload = sentinel_ai_openai.build_grounded_narrative_payload(
        client_keys=[],
        is_global_admin=True,
    )

    assert payload["caasm_snapshot_comparison"] == expected
    assert payload["tenant_scope"]["is_global_admin"] is True
    assert payload["tenant_scope"]["client_keys"] == []


def test_openai_narrative_passes_tenant_scope_to_payload(monkeypatch):
    observed = {}

    monkeypatch.setattr(
        sentinel_ai_openai,
        "openai_configured",
        lambda: True,
    )

    def fake_payload(*, client_keys=None, is_global_admin=False):
        observed["client_keys"] = tuple(client_keys or ())
        observed["is_global_admin"] = is_global_admin
        return {
            "executive_metrics": {},
            "top_remediation_items": [],
            "persistent_open_findings": [],
            "caasm_snapshot_comparison": {
                "available": False
            },
            "tenant_scope": {
                "is_global_admin": is_global_admin,
                "client_keys": list(client_keys or []),
            },
            "instructions": "test",
        }

    monkeypatch.setattr(
        sentinel_ai_openai,
        "build_grounded_narrative_payload",
        fake_payload,
    )

    class FakeResponse:
        output_text = "Scoped narrative"

    class FakeResponses:
        def create(self, **kwargs):
            return FakeResponse()

    class FakeClient:
        responses = FakeResponses()

    class FakeOpenAI:
        def __new__(cls):
            return FakeClient()

    import openai

    monkeypatch.setattr(
        openai,
        "OpenAI",
        FakeOpenAI,
    )

    result = sentinel_ai_openai.generate_openai_executive_narrative(
        client_keys=["tenant-a"],
        is_global_admin=False,
    )

    assert observed["client_keys"] == ("tenant-a",)
    assert observed["is_global_admin"] is False
    assert result["success"] is True
    assert result["narrative"] == "Scoped narrative"
