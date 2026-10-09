import ast
from pathlib import Path
from unittest.mock import Mock

import pandas as pd
import pytest
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from executive_report import generate_pdf, generate_remediation_playbook, load_export_inventory


def test_playbook_prioritizes_kev_severity_and_score_without_losing_rows():
    frame = pd.DataFrame([
        {"Priority": "STANDARD", "CVE ID": "old", "Risk Score": 5, "KEV Exploited": 0},
        {"Priority": "HIGH", "CVE ID": "high", "Risk Score": 90, "KEV Exploited": 0},
        {"Priority": "CRITICAL", "CVE ID": "critical", "Risk Score": 85, "KEV Exploited": 0},
        {"Priority": "LOW", "CVE ID": "kev", "Risk Score": 95, "KEV Exploited": 1},
    ])
    items = generate_remediation_playbook(frame)
    assert [i["CVE ID"] for i in items] == ["kev", "critical", "high", "old"]
    assert items[0]["Priority"] == "CRITICAL"
    assert "Immediate" in items[1]["Remediation Priority"]
    assert frame.iloc[0]["CVE ID"] == "old"


def test_report_wraps_complete_content_and_separates_footers(monkeypatch):
    captured = []
    original = canvas.Canvas.drawString

    def record(self, x, y, text, *args, **kwargs):
        captured.append((self.getPageNumber(), x, y, text))
        return original(self, x, y, text, *args, **kwargs)

    monkeypatch.setattr(canvas.Canvas, "drawString", record)
    # Paragraph uses text objects, not drawString; record those text runs too.
    from reportlab.pdfgen.textobject import PDFTextObject
    original_run = PDFTextObject._textOut
    runs = []

    def record_run(self, text, TStar=0):
        runs.append((self._canvas.getPageNumber(), self._fontname, self._fontsize, text))
        return original_run(self, text, TStar)

    monkeypatch.setattr(PDFTextObject, "_textOut", record_run)
    action = "Review management console access and network controls. " * 10 + "ACTION_END"
    narrative = "Full narrative with <escaped> content and details. " * 30 + "NARRATIVE_END"
    analysis = "Executive analysis recommendations. " * 50 + "ANALYSIS_END"
    items = [{"Priority": "CRITICAL", "CVE ID": "Finding " + "a" * 600,
              "Remediation Priority": action, "Business Impact": "Business disruption"} for _ in range(10)]
    result = generate_pdf(analysis, {"Critical Findings": 4, "Risk Rating": "MODERATE RISK"}, items,
                          narrative, {"Total Clients": 1}, {"Active Client Context": "Example <client>", "Finding Scope": "Shared legacy store"})
    assert result.tell() == 0
    assert result.read().startswith(b"%PDF")
    content = " ".join(run[3] for run in runs)
    assert content.count("ACTION_END") == 10
    assert "NARRATIVE_END" in content and "ANALYSIS_END" in content
    assert "Example <client>" in "".join(run[3] for run in runs)
    assert "Shared legacy store" in content
    for _, font, size, text in runs:
        assert stringWidth(text, font, size) <= 512.1
    footers = [r for r in captured if "Data Generated Solutions" in r[3]]
    assert len(footers) >= 3
    assert len({r[0] for r in footers}) == len(footers)
    assert all(r[2] == 36 for r in footers)


def inventory(**overrides):
    reader = Mock(return_value=[("id", "EC2", "account", "region", "host", "private", "", "stopped", 85, "time")])
    resolver = Mock(return_value="tenant-a")
    options = dict(selected_client=(1, "Example Client"), client_keys=["tenant-a"],
                   is_global_admin=True, visible_clients=[(1, "Example Client"), (2, "Other")],
                   resolve_client_key=resolver, read_assets=reader)
    options.update(overrides)
    return options, reader, resolver


def test_global_admin_selected_client_export_remains_tenant_scoped():
    options, reader, _ = inventory()
    summary = load_export_inventory(**options)
    reader.assert_called_once_with(client_keys=["tenant-a"], is_global_admin=False)
    assert summary["Total Clients"] == 1
    assert summary["Total Assets"] == 1
    assert summary["Critical Assets"] == 1
    assert summary["Stopped Assets"] == 1
    assert summary["Public Assets"] == 0


@pytest.mark.parametrize("override", [{"visible_clients": []}, {"is_global_admin": False, "client_keys": ["tenant-b"]}])
def test_selected_client_denied_before_asset_read(override):
    options, reader, _ = inventory(**override)
    with pytest.raises(PermissionError):
        load_export_inventory(**options)
    reader.assert_not_called()


def test_missing_selected_key_has_no_global_fallback():
    options, reader, resolver = inventory()
    resolver.return_value = None
    with pytest.raises(PermissionError):
        load_export_inventory(**options)
    reader.assert_not_called()


def test_unselected_inventory_uses_authenticated_access_and_empty_metrics():
    options, reader, _ = inventory(selected_client=None, is_global_admin=False)
    reader.return_value = []
    summary = load_export_inventory(**options)
    reader.assert_called_once_with(client_keys=("tenant-a",), is_global_admin=False)
    assert summary["Total Assets"] == 0
    assert summary["Average Asset Risk"] == 0


def test_legacy_findings_reader_denies_non_global_user_without_database_read():
    tree = ast.parse(Path("app.py").read_text())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "safe_get_findings")
    read = Mock(return_value=["legacy"])
    namespace = {"_current_user_is_global_admin": lambda: False, "get_all_findings": read}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "app.py", "exec"), namespace)
    assert namespace["safe_get_findings"]() == []
    read.assert_not_called()
