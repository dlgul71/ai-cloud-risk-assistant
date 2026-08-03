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

def test_splunk_settings_read_environment_values(
    monkeypatch,
):
    monkeypatch.setenv(
        "SPLUNK_HEC_URL",
        "https://splunk.example.com:8088/services/collector",
    )
    monkeypatch.setenv(
        "SPLUNK_HEC_TOKEN",
        "splunk-hec-test-token",  # pragma: allowlist secret
    )
    monkeypatch.setenv(
        "SPLUNK_INDEX",
        "dgs_security",
    )
    monkeypatch.setenv(
        "SPLUNK_SOURCE",
        "dgs_sentinel_test",
    )
    monkeypatch.setenv(
        "SPLUNK_SOURCETYPE",
        "dgs:security:event",
    )
    monkeypatch.setenv(
        "SPLUNK_VERIFY_SSL",
        "false",
    )
    monkeypatch.setenv(
        "SPLUNK_TIMEOUT_SECONDS",
        "20",
    )

    settings = app_config.AppSettings()

    assert settings.splunk_hec_url == (
        "https://splunk.example.com:8088/services/collector"
    )
    assert settings.splunk_hec_token == "splunk-hec-test-token"
    assert settings.splunk_index == "dgs_security"
    assert settings.splunk_source == "dgs_sentinel_test"
    assert settings.splunk_sourcetype == "dgs:security:event"
    assert settings.splunk_verify_ssl is False
    assert settings.splunk_timeout_seconds == 20


def test_splunk_settings_use_safe_defaults(
    monkeypatch,
):
    for key in (
        "SPLUNK_HEC_URL",
        "SPLUNK_HEC_TOKEN",
        "SPLUNK_INDEX",
        "SPLUNK_SOURCE",
        "SPLUNK_SOURCETYPE",
        "SPLUNK_VERIFY_SSL",
        "SPLUNK_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: None,
    )

    settings = app_config.AppSettings()

    assert settings.splunk_hec_url is None
    assert settings.splunk_hec_token is None
    assert settings.splunk_index == "main"
    assert settings.splunk_source == "dgs_sentinel_ai"
    assert settings.splunk_sourcetype == "_json"
    assert settings.splunk_verify_ssl is True
    assert settings.splunk_timeout_seconds == 10


def test_safe_summary_does_not_expose_splunk_token():
    settings = app_config.AppSettings(
        splunk_hec_url=(
            "https://splunk.example.com:8088/services/collector"
        ),
        splunk_hec_token=(
            "splunk-summary-secret-token"
        ),
        splunk_index="dgs_security",
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert "splunk-summary-secret-token" not in rendered_summary
    assert summary["splunk_hec_configured"] is True
    assert summary["splunk_index"] == "dgs_security"


def test_axonius_settings_read_environment_values(
    monkeypatch,
):
    monkeypatch.setenv(
        "AXONIUS_BASE_URL",
        "https://axonius.example.com",
    )
    monkeypatch.setenv(
        "AXONIUS_API_KEY",
        "axonius-test-api-key",
    )
    monkeypatch.setenv(
        "AXONIUS_API_SECRET",
        "axonius-test-api-secret",
    )
    monkeypatch.setenv(
        "AXONIUS_VERIFY_SSL",
        "false",
    )
    monkeypatch.setenv(
        "AXONIUS_TIMEOUT_SECONDS",
        "20",
    )
    monkeypatch.setenv(
        "AXONIUS_ASSETS_PATH",
        "/api/v2/assets",
    )
    monkeypatch.setenv(
        "AXONIUS_IDENTITIES_PATH",
        "/api/v2/identities",
    )

    settings = app_config.AppSettings()

    assert settings.axonius_base_url == (
        "https://axonius.example.com"
    )
    assert settings.axonius_api_key == (
        "axonius-test-api-key"
    )
    assert settings.axonius_api_secret == (
        "axonius-test-api-secret"
    )
    assert settings.axonius_verify_ssl is False
    assert settings.axonius_timeout_seconds == 20
    assert settings.axonius_assets_path == "/api/v2/assets"
    assert (
        settings.axonius_identities_path
        == "/api/v2/identities"
    )


def test_axonius_placeholders_are_not_configured():
    settings = app_config.AppSettings(
        axonius_base_url="https://your-axon-instance",
        axonius_api_key="your-api-key",  # pragma: allowlist secret
        axonius_api_secret="your-api-secret",  # pragma: allowlist secret
    )

    summary = settings.safe_summary()

    assert summary["axonius_configured"] is False


def test_safe_summary_does_not_expose_axonius_secrets():
    settings = app_config.AppSettings(
        axonius_base_url="https://axonius.example.com",
        axonius_api_key="axonius-summary-api-key",  # pragma: allowlist secret
        axonius_api_secret="axonius-summary-api-secret",  # pragma: allowlist secret
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert "axonius-summary-api-key" not in rendered_summary
    assert "axonius-summary-api-secret" not in rendered_summary
    assert summary["axonius_configured"] is True


def test_axonius_settings_use_safe_defaults(
    monkeypatch,
):
    for key in (
        "AXONIUS_BASE_URL",
        "AXONIUS_API_KEY",
        "AXONIUS_API_SECRET",
        "AXONIUS_VERIFY_SSL",
        "AXONIUS_TIMEOUT_SECONDS",
        "AXONIUS_ASSETS_PATH",
        "AXONIUS_IDENTITIES_PATH",
    ):
        monkeypatch.delenv(key, raising=False)

    monkeypatch.setattr(
        app_config,
        "_streamlit_secret",
        lambda key: None,
    )

    settings = app_config.AppSettings()

    assert settings.axonius_base_url is None
    assert settings.axonius_api_key is None
    assert settings.axonius_api_secret is None
    assert settings.axonius_verify_ssl is True
    assert settings.axonius_timeout_seconds == 30
    assert settings.axonius_assets_path == "/api/assets"
    assert settings.axonius_identities_path == "/api/identities"
    assert settings.safe_summary()["axonius_configured"] is False


def test_password_hash_configuration_is_not_exposed():
    password_hash = (
        "pbkdf2_sha256$600000$"
        "30313233343536373839616263646566$"
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )

    settings = app_config.AppSettings(
        app_username="secure-user",
        app_password=None,
        app_password_hash=password_hash,
        max_login_attempts=4,
        account_lockout_minutes=20,
    )

    summary = settings.safe_summary()
    rendered_summary = str(summary)

    assert password_hash not in rendered_summary
    assert "secure-user" not in rendered_summary
    assert summary["app_credentials_configured"] is True
    assert (
        summary["app_password_hash_configured"]
        is True
    )
    assert summary["max_login_attempts"] == 4
    assert summary["account_lockout_minutes"] == 20


def test_login_security_settings_read_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "MAX_LOGIN_ATTEMPTS",
        "7",
    )
    monkeypatch.setenv(
        "ACCOUNT_LOCKOUT_MINUTES",
        "25",
    )
    monkeypatch.setenv(
        "APP_PASSWORD_HASH",
        "test-password-hash",
    )

    settings = app_config.AppSettings()

    assert settings.max_login_attempts == 7
    assert settings.account_lockout_minutes == 25
    assert (
        settings.app_password_hash
        == "test-password-hash"
    )


def test_plaintext_password_remains_compatible():
    settings = app_config.AppSettings(
        app_username="legacy-user",
        app_password="legacy-password",  # pragma: allowlist secret
        app_password_hash=None,
    )

    summary = settings.safe_summary()

    assert summary["app_credentials_configured"] is True
    assert (
        summary["app_password_hash_configured"]
        is False
    )
