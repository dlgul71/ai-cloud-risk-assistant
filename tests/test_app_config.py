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
