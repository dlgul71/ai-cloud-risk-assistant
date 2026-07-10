import app_config


def test_get_setting_prefers_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "UNIT_TEST_SETTING",
        "environment-value",
    )

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: "streamlit-value",
    )

    assert (
        app_config.get_setting(
            "UNIT_TEST_SETTING"
        )
        == "environment-value"
    )


def test_get_setting_uses_streamlit_secret(
    monkeypatch,
):
    monkeypatch.delenv(
        "UNIT_TEST_SETTING",
        raising=False,
    )

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: "streamlit-value",
    )

    assert (
        app_config.get_setting(
            "UNIT_TEST_SETTING"
        )
        == "streamlit-value"
    )


def test_get_first_setting_uses_first_available(
    monkeypatch,
):
    values = {
        "PRIMARY_SETTING": None,
        "secondary.setting": "configured",
    }

    monkeypatch.setattr(
        app_config,
        "get_setting",
        lambda key, *args, **kwargs: values.get(
            key
        ),
    )

    assert (
        app_config.get_first_setting(
            "PRIMARY_SETTING",
            "secondary.setting",
        )
        == "configured"
    )


def test_get_bool_parses_true_values(
    monkeypatch,
):
    monkeypatch.setenv(
        "UNIT_TEST_BOOLEAN",
        "yes",
    )

    assert app_config.get_bool(
        "UNIT_TEST_BOOLEAN"
    ) is True


def test_safe_summary_does_not_expose_secrets():
    settings = app_config.AppSettings(
        app_env="test",
        log_level="INFO",
        aws_region="us-east-1",
        public_demo_mode=False,
        live_remediation_enabled=False,
        session_timeout_minutes=30,
        openai_api_key="openai-secret-value",
        app_username="test-user",
        app_password="password-secret-value",
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert "openai-secret-value" not in rendered_summary
    assert "password-secret-value" not in rendered_summary
    assert summary["openai_configured"] is True
    assert (
        summary["app_credentials_configured"]
        is True
    )


def test_live_remediation_defaults_to_disabled(
    monkeypatch,
):
    monkeypatch.delenv(
        "DGS_LIVE_REMEDIATION_ENABLED",
        raising=False,
    )

    settings = app_config.AppSettings()

    assert settings.live_remediation_enabled is False


def test_live_remediation_can_be_enabled_explicitly(
    monkeypatch,
):
    monkeypatch.setenv(
        "DGS_LIVE_REMEDIATION_ENABLED",
        "true",
    )

    settings = app_config.AppSettings()

    assert settings.live_remediation_enabled is True


def test_safe_summary_does_not_expose_evidence_hmac_key():
    settings = app_config.AppSettings(
        remediation_evidence_hmac_key=(
            "phase-21-summary-secret-0123456789abcdef"
        ),
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert "phase-21-summary-secret" not in rendered_summary
    assert summary["remediation_evidence_hmac_configured"] is True


def test_get_csv_parses_previous_hmac_keys(
    monkeypatch,
):
    monkeypatch.setenv(
        "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS",
        "old-key-one, old-key-two, old-key-one",
    )

    assert app_config.get_csv(
        "DGS_REMEDIATION_EVIDENCE_PREVIOUS_HMAC_KEYS"
    ) == (
        "old-key-one",
        "old-key-two",
        "old-key-one",
    )


def test_safe_summary_reports_previous_key_count_without_secrets():
    settings = app_config.AppSettings(
        remediation_evidence_hmac_key="current-phase22-key",
        remediation_evidence_previous_hmac_keys=(
            "previous-phase22-key-one",
            "previous-phase22-key-two",
        ),
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert "current-phase22-key" not in rendered_summary
    assert "previous-phase22-key-one" not in rendered_summary
    assert summary["remediation_evidence_previous_key_count"] == 2


def test_app_role_defaults_to_administrator(
    monkeypatch,
):
    monkeypatch.delenv(
        "DGS_APP_ROLE",
        raising=False,
    )

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: None,
    )

    settings = app_config.AppSettings()

    assert settings.app_role == "Administrator"


def test_app_role_reads_environment_value(
    monkeypatch,
):
    monkeypatch.setenv(
        "DGS_APP_ROLE",
        "Analyst",
    )

    settings = app_config.AppSettings()

    assert settings.app_role == "Analyst"


def test_safe_summary_reports_role_without_credentials():
    settings = app_config.AppSettings(
        app_username="test-user",
        app_password="test-password",  # pragma: allowlist secret
        app_role="Viewer",
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert summary["app_role"] == "Viewer"
    assert "test-user" not in rendered_summary
    assert "test-password" not in rendered_summary


def test_azure_settings_read_environment_values(
    monkeypatch,
):
    monkeypatch.setenv(
        "AZURE_TENANT_ID",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )
    monkeypatch.setenv(
        "AZURE_CLIENT_ID",
        "11111111-2222-3333-4444-555555555555",
    )
    monkeypatch.setenv(
        "AZURE_CLIENT_SECRET",
        "azure-test-client-secret",
    )
    monkeypatch.setenv(
        "AZURE_SUBSCRIPTION_ID",
        "99999999-8888-7777-6666-555555555555",
    )

    settings = app_config.AppSettings()

    assert (
        settings.azure_tenant_id
        == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    )
    assert (
        settings.azure_client_id
        == "11111111-2222-3333-4444-555555555555"
    )
    assert (
        settings.azure_client_secret
        == "azure-test-client-secret"
    )
    assert (
        settings.azure_subscription_id
        == "99999999-8888-7777-6666-555555555555"
    )


def test_azure_settings_default_to_unconfigured(
    monkeypatch,
):
    for key in (
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: None,
    )

    settings = app_config.AppSettings()

    assert settings.azure_tenant_id is None
    assert settings.azure_client_id is None
    assert settings.azure_client_secret is None
    assert settings.azure_subscription_id is None


def test_safe_summary_reports_azure_without_exposing_secret():
    settings = app_config.AppSettings(
        azure_tenant_id=(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
        azure_client_id=(
            "11111111-2222-3333-4444-555555555555"
        ),
        azure_client_secret=(
            "azure-summary-client-secret"
        ),
        azure_subscription_id=(
            "99999999-8888-7777-6666-555555555555"
        ),
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert summary["azure_configured"] is True
    assert "azure-summary-client-secret" not in rendered_summary
