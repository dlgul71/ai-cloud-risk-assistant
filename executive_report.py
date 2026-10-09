"""Pure executive export formatting, prioritization and inventory scope helpers."""

from datetime import datetime
from io import BytesIO
from html import escape

from pathlib import Path

import pandas as pd
import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


ASSET_COLUMNS = ("Asset ID", "Asset Type", "Account ID", "Region", "Hostname",
                 "Private IP", "Public IP", "State", "Risk Score", "Last Scan")


def generate_remediation_playbook(df):
    items = []
    rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "STANDARD": 1}
    for _, row in df.iterrows():
        priority = str(row.get("Priority", "UNKNOWN")).strip().upper()
        if row.get("KEV Exploited", 0) == 1:
            priority = "CRITICAL"
        if priority == "CRITICAL":
            action = "Immediate patching or isolation required"
            impact = "High exploitation likelihood and potential business disruption"
        elif priority == "HIGH":
            action = "Remediate within standard SLA"
            impact = "Elevated exposure risk"
        else:
            action = "Monitor and remediate during normal patch cycle"
            impact = "Lower immediate business impact"
        score = pd.to_numeric(row.get("Risk Score", 0), errors="coerce")
        score = 0 if pd.isna(score) else float(score)
        items.append({"Priority": priority, "CVE ID": row.get("CVE ID", "Unknown"),
                      "Risk Score": score, "Remediation Priority": action,
                      "Business Impact": impact, "Required Action": row.get("Required Action", "")})
    return sorted(items, key=lambda item: (rank.get(item["Priority"], 0), item["Risk Score"]), reverse=True)


def load_export_inventory(*, selected_client, client_keys, is_global_admin,
                          visible_clients, resolve_client_key, read_assets):
    """A selected client never inherits a global inventory reader fallback."""
    clients = list(visible_clients)
    keys = tuple(client_keys or ())
    if selected_client is not None:
        if not any(client[0] == selected_client[0] for client in clients):
            raise PermissionError("Selected report client is not authorized.")
        key = resolve_client_key(selected_client[0])
        if not key or (not is_global_admin and key not in keys):
            raise PermissionError("Selected report tenant is not authorized.")
        assets = read_assets(client_keys=[key], is_global_admin=False)
        client_count = 1
        scope = "Selected client inventory"
    else:
        assets = read_assets(client_keys=keys, is_global_admin=is_global_admin)
        client_count = len(clients)
        scope = "All authorized client inventory"
    frame = pd.DataFrame(assets, columns=ASSET_COLUMNS)
    scores = pd.to_numeric(frame["Risk Score"], errors="coerce").fillna(0)
    return {"Inventory Scope": scope, "Total Clients": client_count, "Total Assets": len(frame),
            "Average Asset Risk": round(float(scores.mean()), 2) if len(frame) else 0,
            "Critical Assets": int((scores >= 80).sum()),
            "Public Assets": int((frame["Public IP"].notna() & frame["Public IP"].astype(str).str.strip().ne("")).sum()),
            "Stopped Assets": int(frame["State"].eq("stopped").sum())}


def generate_pdf(ai_analysis, summary, remediation_playbook, risk_narrative="",
                 asset_summary=None, report_context=None, company_name="Data Generated Solutions, LLC"):
    """Wrap complete content, paginate sections, and label mixed legacy scope."""
    buffer = BytesIO()
    now = datetime.now()
    document = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=50, rightMargin=50,
                                 topMargin=48, bottomMargin=65,
                                 title="DGS Sentinel AI Executive Cyber Risk Assessment")
    # Embed packaged fonts so rendering does not depend on viewer substitutions.
    fonts = Path(reportlab.__file__).parent / "fonts"
    for name, filename in (("ReportSans", "Vera.ttf"), ("ReportSansBold", "VeraBd.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / filename)))
    styles = getSampleStyleSheet()
    styles["Title"].fontName = "ReportSansBold"
    styles["Heading2"].fontName = "ReportSansBold"
    styles.add(ParagraphStyle("ReportBody", fontName="ReportSans", fontSize=9, leading=13,
                              spaceAfter=7, splitLongWords=True))
    styles.add(ParagraphStyle("ReportSection", parent=styles["Heading2"],
                              textColor=colors.HexColor("#17365D"), keepWithNext=True,
                              spaceBefore=14, spaceAfter=8))
    story = []

    def paragraph(value, style="ReportBody"):
        text = str(value).replace("\u2014", "-").replace("\u2013", "-")
        story.append(Paragraph(escape(text, quote=False).replace("\n", "<br/>"), styles[style]))

    def section(title):
        paragraph(title, "ReportSection")

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("ReportSans", 8)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(50, 36, f"{company_name} | DGS Sentinel AI")
        canvas.drawString(50, 23, f"Generated {now:%Y-%m-%d}")
        canvas.drawRightString(letter[0] - 50, 23, f"Page {doc.page}")
        canvas.restoreState()

    paragraph("DGS Sentinel AI", "Title")
    paragraph("Executive Cyber Risk Assessment Report", "Heading2")
    paragraph(f"Prepared by: {company_name}")
    paragraph(f"Generated: {now:%Y-%m-%d %H:%M:%S}")
    section("Report Scope")
    for key, value in (report_context or {"Finding Scope": "Scope not supplied; do not infer client attribution."}).items():
        paragraph(f"{key}: {value}")
    section("Executive Summary")
    paragraph("DGS Sentinel AI provides executive-level visibility into cloud exposure, identity risk, "
              "threat intelligence, and remediation priorities. This report summarizes key risk indicators, "
              "business impact areas, and recommended actions within the scopes stated above.")
    section("Executive Metrics")
    for key, value in summary.items():
        paragraph(f"{str(key).replace('_', ' ')}: {value}")
    paragraph("The overall rating reflects an aggregate score. Critical findings and known exploited "
              "vulnerability indicators retain their remediation urgency even when the average rating is moderate.")
    if asset_summary:
        section("Asset & Client Exposure Summary")
        for key, value in asset_summary.items():
            paragraph(f"{str(key).replace('_', ' ')}: {value}")
    section("Risk Narrative")
    paragraph(risk_narrative or "No narrative available.")
    section("Top Remediation Priorities")
    for item in remediation_playbook[:10]:
        paragraph(f"{item.get('Priority', '')} | {item.get('CVE ID', item.get('Asset', ''))}")
        paragraph(f"Action: {item.get('Remediation Priority', item.get('Issue', ''))}")
        if item.get("Required Action"):
            paragraph(f"Required Action: {item['Required Action']}")
        paragraph(f"Business Impact: {item.get('Business Impact', '')}")
        story.append(Spacer(1, 4))
    if not remediation_playbook:
        paragraph("No saved remediation items are available for the stated finding scope.")
    section("AI Executive Analysis")
    paragraph(ai_analysis or "No executive analysis available.")
    # Draw after the page content so later-page flowables cannot cover the footer.
    document.afterPage = lambda: footer(document.canv, document)
    document.build(story)
    buffer.seek(0)
    return buffer
