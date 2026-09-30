from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

import headless_scan as scanner


@pytest.fixture
def scan_mock(monkeypatch):
    mock = Mock(return_value=[])
    monkeypatch.setattr(scanner, "run_scan", mock)
    monkeypatch.setattr(scanner.time, "sleep", Mock())
    return mock


@pytest.mark.parametrize("findings", [[], [{"priority": "HIGH"}]])
def test_success_returns_zero(findings, scan_mock, capsys):
    scan_mock.return_value = findings

    assert scanner.main() == 0
    scan_mock.assert_called_once_with()
    output = capsys.readouterr().out
    assert "Security scan completed successfully" in output
    assert "[ERROR]" not in output
    assert "DGS SENTINEL AI HEADLESS MODE COMPLETE" in output


def test_failure_returns_one(scan_mock, capsys):
    scan_mock.side_effect = RuntimeError("simulated scan failure")

    assert scanner.main() == 1
    scan_mock.assert_called_once_with()
    output = capsys.readouterr().out
    assert "[ERROR] Scan failure: simulated scan failure" in output
    assert "Security scan completed successfully" not in output
    assert "DGS SENTINEL AI HEADLESS MODE COMPLETE" in output


@pytest.mark.parametrize("outcome, expected_code", [("success", 0), ("failure", 1)])
def test_cli_exit_status(outcome, expected_code):
    # Replace the engine before loading the actual CLI entry point.
    harness = """
import runpy
import sys
import time
import types

engine = types.ModuleType("scan_engine")

def run_scan():
    if sys.argv[2] == "failure":
        raise RuntimeError("simulated scan failure")
    return []

engine.run_scan = run_scan
sys.modules["scan_engine"] = engine
time.sleep = lambda seconds: None
runpy.run_path(sys.argv[1], run_name="__main__")
"""
    result = subprocess.run(
        [
            sys.executable, "-c", harness,
            str(Path(scanner.__file__).resolve()), outcome,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == expected_code, result.stderr
    assert "DGS SENTINEL AI HEADLESS MODE COMPLETE" in result.stdout
    if outcome == "failure":
        assert "[ERROR] Scan failure: simulated scan failure" in result.stdout
        assert "Security scan completed successfully" not in result.stdout
    else:
        assert "Security scan completed successfully" in result.stdout
        assert "[ERROR]" not in result.stdout
