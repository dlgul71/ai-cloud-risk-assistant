from pathlib import Path

import ai_asset_db


def setup_function():
    ai_asset_db.DB_NAME = "test_ai_assets.db"

    path = Path(ai_asset_db.DB_NAME)

    if path.exists():
        path.unlink()


def teardown_function():
    path = Path(ai_asset_db.DB_NAME)

    if path.exists():
        path.unlink()

    ai_asset_db.DB_NAME = None


def test_save_and_read_ai_asset_for_tenant():
    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-001",
            "asset_type": "AGENT",
            "name": "Customer Service Agent",
            "provider": "OpenAI",
            "environment": "prod",
            "description": "Handles customer requests",
            "risk_score": 70,
            "status": "active",
        },
        client_key="client-a",
    )

    rows = ai_asset_db.get_ai_assets_for_access(
        client_keys=["client-a"],
        is_global_admin=False,
    )

    assert len(rows) == 1
    assert rows[0][0] == "client-a"
    assert rows[0][1] == "agent-001"
    assert rows[0][2] == "AGENT"
    assert rows[0][3] == "Customer Service Agent"
    assert rows[0][7] == 70


def test_tenant_cannot_read_other_tenant_ai_assets():
    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-a",
            "asset_type": "AGENT",
            "name": "Agent A",
        },
        client_key="client-a",
    )

    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-b",
            "asset_type": "AGENT",
            "name": "Agent B",
        },
        client_key="client-b",
    )

    rows = ai_asset_db.get_ai_assets_for_access(
        client_keys=["client-a"],
        is_global_admin=False,
    )

    assert len(rows) == 1
    assert rows[0][0] == "client-a"
    assert rows[0][1] == "agent-a"


def test_global_admin_can_read_all_ai_assets():
    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-a",
            "asset_type": "AGENT",
            "name": "Agent A",
        },
        client_key="client-a",
    )

    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-b",
            "asset_type": "AGENT",
            "name": "Agent B",
        },
        client_key="client-b",
    )

    rows = ai_asset_db.get_ai_assets_for_access(
        is_global_admin=True,
    )

    assert len(rows) == 2


def test_same_ai_asset_id_can_exist_in_two_tenants():
    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "shared-agent",
            "asset_type": "AGENT",
            "name": "Agent A",
        },
        client_key="client-a",
    )

    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "shared-agent",
            "asset_type": "AGENT",
            "name": "Agent B",
        },
        client_key="client-b",
    )

    rows = ai_asset_db.get_ai_assets_for_access(
        is_global_admin=True,
    )

    assert len(rows) == 2


def test_save_and_read_ai_relationship():
    ai_asset_db.save_ai_asset_relationship(
        client_key="client-a",
        source_asset_id="agent-001",
        relationship_type="uses_model",
        target_asset_id="model-001",
    )

    rows = ai_asset_db.get_ai_relationships_for_access(
        client_keys=["client-a"],
        is_global_admin=False,
    )

    assert len(rows) == 1
    assert rows[0][0] == "client-a"
    assert rows[0][1] == "agent-001"
    assert rows[0][2] == "USES_MODEL"
    assert rows[0][3] == "model-001"


def test_relationships_are_tenant_scoped():
    ai_asset_db.save_ai_asset_relationship(
        client_key="client-a",
        source_asset_id="agent-a",
        relationship_type="calls_tool",
        target_asset_id="tool-a",
    )

    ai_asset_db.save_ai_asset_relationship(
        client_key="client-b",
        source_asset_id="agent-b",
        relationship_type="calls_tool",
        target_asset_id="tool-b",
    )

    rows = ai_asset_db.get_ai_relationships_for_access(
        client_keys=["client-a"],
        is_global_admin=False,
    )

    assert len(rows) == 1
    assert rows[0][0] == "client-a"
    assert rows[0][1] == "agent-a"
    assert rows[0][3] == "tool-a"


def test_missing_client_key_fails_closed():
    try:
        ai_asset_db.save_ai_asset(
            {
                "ai_asset_id": "agent-001",
                "asset_type": "AGENT",
                "name": "Agent",
            }
        )
    except ValueError as exc:
        assert str(exc) == "client_key is required"
    else:
        raise AssertionError(
            "Expected missing client_key to fail"
        )


def test_empty_client_access_returns_no_rows():
    ai_asset_db.save_ai_asset(
        {
            "ai_asset_id": "agent-001",
            "asset_type": "AGENT",
            "name": "Agent",
        },
        client_key="client-a",
    )

    rows = ai_asset_db.get_ai_assets_for_access(
        client_keys=[],
        is_global_admin=False,
    )

    assert rows == []
