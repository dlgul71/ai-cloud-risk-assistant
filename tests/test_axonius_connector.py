from types import SimpleNamespace

import pytest
import requests

import axonius_connector


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        payload=None,
        json_error=False,
    ):
        self.status_code = status_code
        self.payload = (
            {"data": []}
            if payload is None
            else payload
        )
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("Invalid JSON")

        return self.payload


def configured_settings():
    return SimpleNamespace(
        axonius_base_url="https://axonius.example.com",
        axonius_api_key="test-api-key",  # pragma: allowlist secret
        axonius_api_secret="test-api-secret",  # pragma: allowlist secret
        axonius_verify_ssl=True,
        axonius_timeout_seconds=15,
    )


def test_normalize_axonius_url_accepts_https():
    assert axonius_connector.normalize_axonius_url(
        "https://axonius.example.com/"
    ) == "https://axonius.example.com"


def test_normalize_axonius_url_rejects_http():
    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="valid HTTPS URL",
    ):
        axonius_connector.normalize_axonius_url(
            "http://axonius.example.com"
        )


def test_normalize_axonius_url_rejects_credentials():
    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="embedded credentials",
    ):
        axonius_connector.normalize_axonius_url(
            "https://user:password@axonius.example.com"  # pragma: allowlist secret
        )


def test_axonius_configured_rejects_placeholders(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        SimpleNamespace(
            axonius_base_url="https://your-axon-instance",
            axonius_api_key="your-api-key",  # pragma: allowlist secret
            axonius_api_secret="your-api-secret",  # pragma: allowlist secret
        ),
    )

    assert axonius_connector.axonius_configured() is False


def test_get_assets_returns_mock_data_when_unconfigured(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        SimpleNamespace(
            axonius_base_url=None,
            axonius_api_key=None,
            axonius_api_secret=None,
        ),
    )

    result = axonius_connector.get_axonius_assets()

    assert result["mode"] == "Mock"
    assert len(result["assets"]) == 3


def test_get_assets_live_request(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    captured = {}

    def fake_get(
        url,
        *,
        headers,
        timeout,
        verify,
    ):
        captured.update(
            {
                "url": url,
                "headers": headers,
                "timeout": timeout,
                "verify": verify,
            }
        )

        return FakeResponse(
            payload={
                "data": [
                    {
                        "asset_id": "asset-001",
                        "hostname": "server-001",
                    }
                ]
            }
        )

    result = axonius_connector.get_axonius_assets(
        http_get=fake_get
    )

    assert result["mode"] == "Live"
    assert result["assets"][0]["asset_id"] == "asset-001"
    assert captured["url"] == (
        "https://axonius.example.com/api/assets"
    )
    assert captured["headers"]["api-key"] == "test-api-key"
    assert captured["headers"]["api-secret"] == (
        "test-api-secret"
    )
    assert captured["timeout"] == 15
    assert captured["verify"] is True


def test_get_identities_live_request(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    def fake_get(*args, **kwargs):
        return FakeResponse(
            payload={
                "identities": [
                    {
                        "identity_id": "user-001",
                        "username": "admin",
                    }
                ]
            }
        )

    result = axonius_connector.get_axonius_identities(
        http_get=fake_get
    )

    assert result["mode"] == "Live"
    assert result["identities"][0]["identity_id"] == (
        "user-001"
    )


def test_live_request_rejects_http_error(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    def fake_get(*args, **kwargs):
        return FakeResponse(status_code=401)

    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="HTTP status 401",
    ):
        axonius_connector.get_axonius_assets(
            http_get=fake_get
        )


def test_live_request_rejects_invalid_json(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    def fake_get(*args, **kwargs):
        return FakeResponse(json_error=True)

    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="invalid JSON",
    ):
        axonius_connector.get_axonius_assets(
            http_get=fake_get
        )


def test_live_request_wraps_connection_error(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    def fake_get(*args, **kwargs):
        raise requests.ConnectionError(
            "Connection failed"
        )

    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="request failed",
    ):
        axonius_connector.get_axonius_assets(
            http_get=fake_get
        )


def test_live_request_requires_positive_timeout(
    monkeypatch,
):
    settings = configured_settings()
    settings.axonius_timeout_seconds = 0

    monkeypatch.setattr(
        axonius_connector,
        "settings",
        settings,
    )

    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="greater than zero",
    ):
        axonius_connector.get_axonius_assets()


def test_connection_reports_not_configured(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        SimpleNamespace(
            axonius_base_url=None,
            axonius_api_key=None,
            axonius_api_secret=None,
        ),
    )

    result = axonius_connector.test_axonius_connection()

    assert result == {
        "status": "NOT_CONFIGURED",
        "mode": "Mock",
        "asset_count": 0,
        "message": "Axonius is not configured.",
    }


def test_connection_reports_live_asset_count(
    monkeypatch,
):
    monkeypatch.setattr(
        axonius_connector,
        "settings",
        configured_settings(),
    )

    def fake_get(*args, **kwargs):
        return FakeResponse(
            payload={
                "data": [
                    {"asset_id": "asset-001"},
                    {"asset_id": "asset-002"},
                ]
            }
        )

    result = axonius_connector.test_axonius_connection(
        http_get=fake_get
    )

    assert result == {
        "status": "CONNECTED",
        "mode": "Live",
        "asset_count": 2,
        "message": "Axonius API connection succeeded.",
    }


def test_normalize_axonius_path_accepts_relative_path():
    assert axonius_connector.normalize_axonius_path(
        "/api/v2/assets"
    ) == "/api/v2/assets"


def test_normalize_axonius_path_rejects_absolute_url():
    with pytest.raises(
        axonius_connector.AxoniusConnectorError,
        match="relative API path",
    ):
        axonius_connector.normalize_axonius_path(
            "https://attacker.example.com/assets"
        )


def test_live_request_uses_configured_asset_path(
    monkeypatch,
):
    settings = configured_settings()
    settings.axonius_assets_path = "/api/v2/assets"

    monkeypatch.setattr(
        axonius_connector,
        "settings",
        settings,
    )

    captured = {}

    def fake_get(url, **kwargs):
        captured["url"] = url
        return FakeResponse(payload={"data": []})

    axonius_connector.get_axonius_assets(
        http_get=fake_get
    )

    assert captured["url"] == (
        "https://axonius.example.com/api/v2/assets"
    )
