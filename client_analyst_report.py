from io import BytesIO
from datetime import datetime
from html import escape
from pathlib import Path
import reportlab
from demo_mode import sanitize_text

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, KeepTogether

from sentinel_ai_analyst import (
    build_security_context_for_access,
    get_available_clients_for_access,
    filter_context_by_account,
    calculate_analyst_metrics,
    get_top_remediation_items
)


COMPANY_NAME = "Data Generated Solutions, LLC"


def generate_client_analyst_pdf(
    client_name,
    aws_account_id,
    *,
    client_keys=None,
    is_global_admin=False,
):
    real_aws_account_id = str(aws_account_id or "").strip()
    if not real_aws_account_id:
        raise ValueError("AWS account ID is required for a client report.")

    client_keys = tuple(client_keys or ())
    visible_clients = get_available_clients_for_access(
        client_keys=client_keys,
        is_global_admin=is_global_admin,
    )
    authorized_accounts = {
        str(client.get("aws_account_id") or "").strip()
        for client in visible_clients
        if client.get("aws_account_id")
    }
    if real_aws_account_id not in authorized_accounts:
        raise PermissionError("The selected AWS account is not authorized.")

    real_client_name = client_name

    display_client_name = sanitize_text(
        real_client_name
    )

    display_aws_account_id = sanitize_text(
        real_aws_account_id
    )

    context = build_security_context_for_access(
        client_keys=client_keys,
        is_global_admin=is_global_admin,
    )

    filtered_context = filter_context_by_account(
        context=context,
        aws_account_id=real_aws_account_id
    )

    metrics = calculate_analyst_metrics(
        filtered_context
    )

    top_items = get_top_remediation_items(
        filtered_context,
        limit=10
    )

    buffer = BytesIO()
    now = datetime.now()
    fonts = Path(reportlab.__file__).parent / "fonts"
    for name, filename in (("ReportSans", "Vera.ttf"), ("ReportSansBold", "VeraBd.ttf")):
        if name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(name, str(fonts / filename)))
    styles = getSampleStyleSheet()
    styles["Title"].fontName = "ReportSansBold"
    styles["Heading2"].fontName = "ReportSansBold"
    styles.add(ParagraphStyle("ClientBody", fontName="ReportSans", fontSize=9,
                              leading=13, spaceAfter=7, splitLongWords=True))
    styles.add(ParagraphStyle("ClientSection", parent=styles["Heading2"],
                              textColor=colors.HexColor("#17365D"), keepWithNext=True,
                              spaceBefore=14, spaceAfter=8))
    story = []

    def paragraph(value, style="ClientBody"):
        text = sanitize_text(str(value)).replace("\u2014", "-").replace("\u2013", "-")
        return Paragraph(escape(text, quote=False).replace("\n", "<br/>"), styles[style])

    def write_line(value, style="ClientBody"):
        story.append(paragraph(value, style))

    def write_section(value):
        write_line(value, "ClientSection")

    def footer(pdf, doc):
        pdf.saveState()
        pdf.setFont("ReportSans", 8)
        pdf.setFillColor(colors.HexColor("#555555"))
        pdf.drawString(50, 36, f"{COMPANY_NAME} | DGS Sentinel AI")
        pdf.drawString(50, 23, f"Generated {now:%Y-%m-%d}")
        pdf.drawRightString(letter[0] - 50, 23, f"Page {doc.page}")
        pdf.restoreState()

    write_line("DGS Sentinel AI", "Title")
    write_line("Client Cloud Security Assessment Report", "Heading2")
    write_line(f"Prepared by: {COMPANY_NAME}")
    write_line(f"Client: {display_client_name}")
    write_line(f"AWS Account ID: {display_aws_account_id}")
    write_line(f"Generated: {now:%Y-%m-%d %H:%M:%S}")
    write_section("Client-Scoped Executive Metrics")
    for name in ("Total Assets", "Public Assets", "Critical Remediation Items",
                 "High Remediation Items", "Open Remediation Items", "Persistent Findings"):
        write_line(f"{name}: {metrics.get(name, 0)}")
    write_line("Execution and CAASM metrics are excluded from this client-specific section "
               "until those records contain AWS-account correlation.")
    write_section("Top Client Remediation Priorities")
    for index, item in enumerate(top_items, start=1):
        heading = (f"{index}. {item.get('priority', 'STANDARD')} | "
                   f"{item.get('category', 'Unknown')} | "
                   f"{item.get('finding', 'Unknown Finding')} | "
                   f"Risk Score: {item.get('risk_score', 0)}")
        recommendation = "Recommendation: " + str(item.get("recommendation", "Review and remediate per SLA."))
        story.append(KeepTogether([paragraph(heading), paragraph(recommendation)]))
        story.append(Spacer(1, 5))
    if not top_items:
        write_line("No client-specific remediation records are available yet. "
                   "Run a new scan for this AWS account.")
    write_section("Recommended Client Focus")
    for line in ("1. Review public-facing assets and validate business need.",
                 "2. Address critical and high-risk remediation items.",
                 "3. Validate IAM, MFA, and credential hygiene.",
                 "4. Review Security Hub and GuardDuty findings.",
                 "5. Run recurring scans and compare historical trends."):
        write_line(line)
    write_section("Assessment Notes")
    for line in ("This report is generated from saved DGS Sentinel AI platform data for the selected AWS account.",
                 "The current assessment workflow is read-only. No AWS resources were modified.",
                 "Remediation recommendations should be validated with the client before implementation."):
        write_line(line)
    document = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=50, rightMargin=50,
                                 topMargin=48, bottomMargin=65,
                                 title="DGS Sentinel AI Client Cloud Security Assessment")
    document.afterPage = lambda: footer(document.canv, document)
    document.build(story, canvasmaker=canvas.Canvas)
    buffer.seek(0)
    return buffer
