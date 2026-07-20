import pytest
import requests

import splunk_hec


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        body=None,
        json_error=False,
    ):
        self.status_code = status_code
        self.body = (
            {"text": "Success", "code": 0}
            if body is None
            else body
        )
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("Invalid JSON")

        return self.body


def test_normalize_hec_url_adds_event_endpoint():
    assert splunk_hec.normalize_hec_url(
        "https://splunk.example.com:8088"
    ) == (
        "https://splunk.example.com:8088"
        "/services/collector/event"
    )


def test_normalize_hec_url_preserves_collector_endpoint():
    assert splunk_hec.normalize_hec_url(
        "https://splunk.example.com:8088/services/collector"
    ) == (
        "https://splunk.example.com:8088"
        "/services/collector/event"
    )


def test_normalize_hec_url_rejects_embedded_credentials():
    with pytest.raises(
        splunk_hec.SplunkHECError,
        match="embedded credentials",
    ):
        splunk_hec.normalize_hec_url(
            "https://user:password@splunk.example.com:8088"  # pragma: allowlist secret
        )


def test_build_hec_payload_includes_metadata():
    payload = splunk_hec.build_hec_payload(
        {"severity": "HIGH"},
        index="dgs_security",
        source="dgs_sentinel_ai",
        sourcetype="dgs:security:event",
        host="sentinel-node",
        event_time=1234.5,
        fields={"cloud": "azure"},
    )

    assert payload == {
        "time": 1234.5,
        "index": "dgs_security",
        "source": "dgs_sentinel_ai",
        "sourcetype": "dgs:security:event",
        "host": "sentinel-node",
        "fields": {"cloud": "azure"},
        "event": {"severity": "HIGH"},
    }


def test_send_event_posts_authenticated_payload():
    captured = {}

    def fake_post(
        url,
        *,
        headers,
        json,
        timeout,
        verify,
    ):
        captured.update(
            {
                "url": url,
                "headers": headers,
                "json": json,
                "timeout": timeout,
                "verify": verify,
            }
        )
        return FakeResponse()

    result = splunk_hec.send_event(
        {"event_type": "remediation_completed"},
        hec_url="https://splunk.example.com:8088",
        token="test-hec-token",
        index="dgs_security",
        source="dgs_sentinel_test",
        sourcetype="dgs:security:event",
        verify_ssl=True,
        timeout_seconds=15,
        http_post=fake_post,
    )

    assert result["status"] == "SENT"
    assert result["http_status"] == 200
    assert captured["url"].endswith(
        "/services/collector/event"
    )
    assert captured["headers"]["Authorization"] == (
        "Splunk test-hec-token"
    )
    assert captured["json"]["event"] == {
        "event_type": "remediation_completed"
    }
    assert captured["timeout"] == 15
    assert captured["verify"] is True


def test_send_event_rejects_missing_token():
    with pytest.raises(
        splunk_hec.SplunkHECError,
        match="token is not configured",
    ):
        splunk_hec.send_event(
            {"event": "test"},
            hec_url="https://splunk.example.com:8088",
            token="",
        )


def test_send_event_rejects_http_error():
    def fake_post(*args, **kwargs):
        return FakeResponse(status_code=503)

    with pytest.raises(
        splunk_hec.SplunkHECError,
        match="HTTP status 503",
    ):
        splunk_hec.send_event(
            {"event": "test"},
            hec_url="https://splunk.example.com:8088",
            token="test-token",
            http_post=fake_post,
        )


def test_send_event_rejects_splunk_error_code():
    def fake_post(*args, **kwargs):
        return FakeResponse(
            body={
                "text": "Invalid token",
                "code": 4,
            }
        )

    with pytest.raises(
        splunk_hec.SplunkHECError,
        match="Invalid token",
    ):
        splunk_hec.send_event(
            {"event": "test"},
            hec_url="https://splunk.example.com:8088",
            token="test-token",
            http_post=fake_post,
        )


def test_send_event_wraps_request_exception():
    def fake_post(*args, **kwargs):
        raise requests.ConnectionError("Connection failed")

    with pytest.raises(
        splunk_hec.SplunkHECError,
        match="request failed",
    ):
        splunk_hec.send_event(
            {"event": "test"},
            hec_url="https://splunk.example.com:8088",
            token="test-token",
            http_post=fake_post,
        )
