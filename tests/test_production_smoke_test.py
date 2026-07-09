from scripts import production_smoke_test


def test_run_smoke_tests_passes_when_endpoints_are_healthy(
    monkeypatch,
):
    monkeypatch.setattr(
        production_smoke_test,
        "check_endpoint",
        lambda url, expected_body=None, timeout=5.0: (
            True,
            "HTTP 200",
        ),
    )

    results = production_smoke_test.run_smoke_tests(
        "http://127.0.0.1:8502"
    )

    assert len(results) == 2
    assert all(result["status"] == "PASS" for result in results)


def test_run_smoke_tests_reports_endpoint_failure(
    monkeypatch,
):
    def fake_check(url, expected_body=None, timeout=5.0):
        if url.endswith("/_stcore/health"):
            return False, "Unexpected response body"
        return True, "HTTP 200"

    monkeypatch.setattr(
        production_smoke_test,
        "check_endpoint",
        fake_check,
    )

    results = production_smoke_test.run_smoke_tests(
        "http://127.0.0.1:8502/"
    )

    assert results[0]["status"] == "PASS"
    assert results[1]["status"] == "FAIL"


def test_main_returns_success_for_healthy_deployment(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        production_smoke_test,
        "run_smoke_tests",
        lambda base_url, timeout: [
            {
                "check": "Application root",
                "status": "PASS",
                "detail": "HTTP 200",
                "url": base_url,
            }
        ],
    )

    result = production_smoke_test.main(
        ["--base-url", "http://127.0.0.1:8502"]
    )

    assert result == 0
    assert "smoke test passed" in capsys.readouterr().out


def test_main_returns_failure_for_unhealthy_deployment(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        production_smoke_test,
        "run_smoke_tests",
        lambda base_url, timeout: [
            {
                "check": "Streamlit health endpoint",
                "status": "FAIL",
                "detail": "Connection refused",
                "url": base_url,
            }
        ],
    )

    result = production_smoke_test.main(
        ["--base-url", "http://127.0.0.1:8502"]
    )

    assert result == 1
    assert "smoke test failed" in capsys.readouterr().out
