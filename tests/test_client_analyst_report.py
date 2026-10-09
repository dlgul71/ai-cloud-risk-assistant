"""Client PDF authorization and rendering regressions; no live services."""
import ast
from pathlib import Path
from unittest.mock import Mock

import pytest

import client_analyst_report as report
import demo_mode
import sentinel_ai_analyst as analyst


ACCOUNT = "111111111111"
OTHER_ACCOUNT = "222222222222"


def finding(label, account=ACCOUNT, score=90):
    return {
        "finding": label, "aws_account_id": account,
        "priority": "CRITICAL", "category": "Cloud",
        "recommendation": "Review access.", "risk_score": score,
        "status": "Open", "occurrence_count": 2,
    }


@pytest.fixture
def isolated_report(monkeypatch):
    context = {
        "assets": [
            {"account_id": ACCOUNT, "public_ip": "203.0.113.10"},
            {"account_id": OTHER_ACCOUNT, "public_ip": None},
        ],
        "remediation_items": [finding("GLOBAL_ONLY")],
        "remediation_items_with_context": [
            finding("AUTHORIZED_FINDING"),
            finding("FOREIGN_FINDING", OTHER_ACCOUNT, 100),
        ],
        "execution_actions": [{"execution_status": "Completed"}],
        "latest_caasm_snapshot": {"metrics": {"CAASM Score": 99}},
        "caasm_snapshot_count": 5,
    }
    clients = Mock(return_value=[{"aws_account_id": ACCOUNT}])
    build = Mock(return_value=context)
    monkeypatch.setattr(report, "get_available_clients_for_access", clients)
    monkeypatch.setattr(report, "build_security_context_for_access", build)
    monkeypatch.setattr(demo_mode, "DEMO_MODE", False)
    # Record text while still generating a real ReportLab PDF.
    real_canvas = report.canvas.Canvas
    rendered = []

    class RecordingCanvas(real_canvas):
        def drawString(self, x, y, text, *args, **kwargs):
            rendered.append((self.getPageNumber(), x, y, text))
            return super().drawString(x, y, text, *args, **kwargs)

    monkeypatch.setattr(report.canvas, "Canvas", RecordingCanvas)
    from reportlab.pdfgen.textobject import PDFTextObject
    original_run = PDFTextObject._textOut

    def record_run(self, text, TStar=0):
        rendered.append((self._canvas.getPageNumber(), None, None, text))
        return original_run(self, text, TStar)

    monkeypatch.setattr(PDFTextObject, "_textOut", record_run)

    return context, clients, build, rendered


def render_text(state):
    return "\n".join(row[3] for row in state[3])


def generate(**kwargs):
    return report.generate_client_analyst_pdf(
        "Example Client", ACCOUNT, client_keys=["tenant-a"], **kwargs
    )


@pytest.mark.parametrize("account", [None, "", "   "])
def test_missing_account_fails_before_loading_data(account, isolated_report):
    _, clients, build, rendered = isolated_report
    with pytest.raises(ValueError, match="account ID is required"):
        report.generate_client_analyst_pdf("Example", account)
    clients.assert_not_called()
    build.assert_not_called()
    assert rendered == []


@pytest.mark.parametrize("clients", [[], [{"aws_account_id": OTHER_ACCOUNT}]])
def test_unauthorized_account_fails_before_loading_data(clients, isolated_report):
    isolated_report[1].return_value = clients
    with pytest.raises(PermissionError, match="not authorized"):
        generate()
    isolated_report[2].assert_not_called()
    assert isolated_report[3] == []


def test_no_access_arguments_default_to_denial(isolated_report):
    isolated_report[1].return_value = []
    with pytest.raises(PermissionError):
        report.generate_client_analyst_pdf("Example", ACCOUNT)
    isolated_report[1].assert_called_once_with(
        client_keys=(), is_global_admin=False
    )
    isolated_report[2].assert_not_called()


def test_pdf_filters_authorized_account_and_returns_rewound_buffer(isolated_report):
    buffer = generate()
    assert buffer.tell() == 0
    assert buffer.read(5) == b"%PDF-"
    assert buffer.getvalue().rstrip().endswith(b"%%EOF")
    for boundary in isolated_report[1:3]:
        boundary.assert_called_once_with(
            client_keys=("tenant-a",), is_global_admin=False
        )
    text = render_text(isolated_report)
    assert "Total Assets: 1" in text
    assert "Public Assets: 1" in text
    assert "Critical Remediation Items: 1" in text
    assert "Open Remediation Items: 1" in text
    assert "Persistent Findings: 1" in text
    assert "AUTHORIZED_FINDING" in text
    assert "FOREIGN_FINDING" not in text
    assert "GLOBAL_ONLY" not in text
    assert "CAASM Score:" not in text
    assert "Completed Simulation Actions:" not in text


def test_empty_authorized_account_generates_report(isolated_report):
    isolated_report[2].return_value = {}
    generate()
    text = render_text(isolated_report)
    assert "Total Assets: 0" in text
    assert "No client-specific remediation records are available yet." in text


def test_explicit_global_admin_still_filters_selected_account(isolated_report):
    report.generate_client_analyst_pdf(
        "Example", ACCOUNT, is_global_admin=True
    )
    isolated_report[2].assert_called_once_with(
        client_keys=(), is_global_admin=True
    )
    assert "AUTHORIZED_FINDING" in render_text(isolated_report)
    assert "FOREIGN_FINDING" not in render_text(isolated_report)


def test_shared_account_keeps_tenant_boundary(monkeypatch, isolated_report):
    # Use the real scoped context builder and account filter. Two tenants
    # share an AWS account; the database boundary selects only assigned keys.
    monkeypatch.setattr(
        report, "build_security_context_for_access",
        analyst.build_security_context_for_access,
    )
    global_build = Mock(side_effect=AssertionError("Global data requested"))
    monkeypatch.setattr(analyst, "build_security_context", global_build)
    asset_rows = {
        "tenant-a": [("asset-a", "EC2", ACCOUNT, "us-east-1",
                      "host-a", None, None, "running", 50, "2026-09-30")],
        "tenant-b": [("asset-b", "EC2", ACCOUNT, "us-east-1",
                      "host-b", None, None, "running", 99, "2026-09-30")],
    }

    def rows_for_access(*, client_keys, is_global_admin):
        assert not is_global_admin
        return [row for key in client_keys for row in asset_rows[key]]

    def remediation_for_key(key):
        marker = "TENANT_A_ONLY" if key == "tenant-a" else "TENANT_B_SECRET"
        return [(1, "2026-09-30", "Cloud", "HIGH", marker, "Review access.",
                 "Security", "Open", 70, 1, "2026-09-30", ACCOUNT, key)]

    assets = Mock(side_effect=rows_for_access)
    remediation = Mock(side_effect=lambda **kwargs: [
        row[:11] for key in kwargs["client_keys"]
        for row in remediation_for_key(key)
    ])
    context_rows = Mock(side_effect=remediation_for_key)
    monkeypatch.setattr(analyst, "get_assets_for_access", assets)
    monkeypatch.setattr(analyst, "get_remediation_items_for_access", remediation)
    monkeypatch.setattr(
        analyst, "get_remediation_items_with_client_context", context_rows
    )
    generate()
    assets.assert_called_once_with(
        client_keys=("tenant-a",), is_global_admin=False
    )
    context_rows.assert_called_once_with("tenant-a")
    global_build.assert_not_called()
    text = render_text(isolated_report)
    assert "Total Assets: 1" in text
    assert "TENANT_A_ONLY" in text
    assert "TENANT_B_SECRET" not in text


def test_display_sanitization_does_not_change_account_selection(
    monkeypatch, isolated_report
):
    monkeypatch.setattr(
        report, "sanitize_text",
        lambda value: str(value).replace(ACCOUNT, "REDACTED_ACCOUNT"),
    )
    report.generate_client_analyst_pdf(
        "Example", f" {ACCOUNT} ", client_keys=["tenant-a"]
    )
    text = render_text(isolated_report)
    assert "AWS Account ID: REDACTED_ACCOUNT" in text
    assert ACCOUNT not in text
    assert "AUTHORIZED_FINDING" in text
    assert "FOREIGN_FINDING" not in text


def test_long_report_paginates_and_limits_priorities(isolated_report):
    isolated_report[0]["remediation_items_with_context"] = [
        dict(finding(f"PRIORITY_{i:02d}", score=100-i),
             recommendation="Review this control. " * 80)
        for i in range(12)
    ]
    buffer = generate()
    assert buffer.getvalue().startswith(b"%PDF-")
    pages = {row[0] for row in isolated_report[3]}
    assert len(pages) > 1
    text = render_text(isolated_report)
    assert "PRIORITY_00" in text
    assert "PRIORITY_09" in text
    assert "PRIORITY_10" not in text
    assert "PRIORITY_11" not in text
    assert "Assessment Notes" in text


def test_data_failure_does_not_render_successful_report(isolated_report):
    isolated_report[2].side_effect = RuntimeError("storage unavailable")
    with pytest.raises(RuntimeError, match="storage unavailable"):
        generate()
    assert isolated_report[3] == []


def test_app_pdf_exports_forward_authenticated_access():
    tree = ast.parse(
        (Path(__file__).resolve().parents[1] / "app.py").read_text()
    )
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "generate_client_analyst_pdf"
    ]
    assert len(calls) == 2
    for call in calls:
        keywords = {item.arg: item.value for item in call.keywords}
        for name, helper in (
            ("client_keys", "_current_user_client_keys"),
            ("is_global_admin", "_current_user_is_global_admin"),
        ):
            value = keywords[name]
            assert isinstance(value, ast.Call)
            assert isinstance(value.func, ast.Name)
            assert value.func.id == helper


def test_long_words_complete_content_and_single_footer_per_page(isolated_report, monkeypatch):
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen.textobject import PDFTextObject
    widths = []
    original = PDFTextObject._textOut

    def capture(self, text, TStar=0):
        widths.append(stringWidth(text, self._fontname, self._fontsize))
        return original(self, text, TStar)

    monkeypatch.setattr(PDFTextObject, "_textOut", capture)
    isolated_report[0]["remediation_items_with_context"] = [
        dict(finding("FINDING_START " + "x" * 700 + " FINDING_END", score=100-i),
             recommendation="Review affected resources and validate evidence. " * 30 + "RECOMMENDATION_END")
        for i in range(10)
    ]
    generate()
    text = render_text(isolated_report)
    assert text.count("FINDING_END") == 10
    assert text.count("RECOMMENDATION_END") == 10
    assert max(widths) <= 512.1
    footers = [row for row in isolated_report[3] if row[2] == 36]
    pages = {row[0] for row in isolated_report[3]}
    assert len(pages) > 1
    assert {row[0] for row in footers} == pages
    assert len(footers) == len(pages)
    assert "Assessment Notes" in text
