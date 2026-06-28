from io import BytesIO
from datetime import datetime
from demo_mode import sanitize_text

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from sentinel_ai_analyst import (
    build_security_context,
    filter_context_by_account,
    calculate_analyst_metrics,
    get_top_remediation_items
)


COMPANY_NAME = "Data Generated Solutions, LLC"


def generate_client_analyst_pdf(
    client_name,
    aws_account_id
):
    real_client_name = client_name
    real_aws_account_id = aws_account_id

    display_client_name = sanitize_text(
        real_client_name
    )

    display_aws_account_id = sanitize_text(
        real_aws_account_id
    )

    context = build_security_context()

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
    pdf = canvas.Canvas(
        buffer,
        pagesize=letter
    )

    width, height = letter
    y = height - 60

    def add_footer():
        pdf.setFont("Helvetica", 8)

        pdf.drawString(
            50,
            30,
            (
                "Data Generated Solutions, LLC | "
                "DGS Sentinel AI Client Security Assessment"
            )
        )

        pdf.drawRightString(
            width - 50,
            30,
            f"Generated {datetime.now().strftime('%Y-%m-%d')}"
        )

    def new_page():
        pdf.showPage()
        add_footer()

        return height - 60

    def write_section(title):
        nonlocal y

        if y < 100:
            y = new_page()

        pdf.setFont(
            "Helvetica-Bold",
            12
        )

        pdf.drawString(
            50,
            y,
            title
        )

        y -= 18

        pdf.setFont(
            "Helvetica",
            9
        )

    def write_line(
        line,
        indent=65,
        max_chars=105
    ):
        nonlocal y

        remaining_text = sanitize_text(
            str(line)
        ).strip()

        while remaining_text:
            if y < 80:
                y = new_page()

                pdf.setFont(
                    "Helvetica",
                    9
                )

            segment = remaining_text[
                :max_chars
            ]

            pdf.drawString(
                indent,
                y,
                segment
            )

            remaining_text = remaining_text[
                max_chars:
            ]

            y -= 13

    pdf.setFont(
        "Helvetica-Bold",
        20
    )

    pdf.drawString(
        50,
        y,
        "DGS Sentinel AI"
    )

    y -= 25

    pdf.setFont(
        "Helvetica-Bold",
        14
    )

    pdf.drawString(
        50,
        y,
        "Client Cloud Security Assessment Report"
    )

    y -= 20

    pdf.setFont(
        "Helvetica",
        10
    )

    pdf.drawString(
        50,
        y,
        f"Prepared by: {COMPANY_NAME}"
    )

    y -= 15

    pdf.drawString(
        50,
        y,
        f"Client: {display_client_name}"
    )

    y -= 15

    pdf.drawString(
        50,
        y,
        f"AWS Account ID: {display_aws_account_id}"
    )

    y -= 15

    pdf.drawString(
        50,
        y,
        (
            "Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    )

    y -= 30

    write_section(
        "Client-Scoped Executive Metrics"
    )

    client_metric_names = [
        "Total Assets",
        "Public Assets",
        "Critical Remediation Items",
        "High Remediation Items",
        "Open Remediation Items",
        "Persistent Findings"
    ]

    for metric_name in client_metric_names:
        write_line(
            f"{metric_name}: {metrics.get(metric_name, 0)}"
        )

    write_line(
        (
            "Execution and CAASM metrics are excluded from this "
            "client-specific section until those records contain "
            "AWS-account correlation."
        )
    )

    y -= 12

    write_section(
        "Top Client Remediation Priorities"
    )

    if top_items:
        for index, item in enumerate(
            top_items,
            start=1
        ):
            write_line(
                (
                    f"{index}. "
                    f"{item.get('priority', 'STANDARD')} | "
                    f"{item.get('category', 'Unknown')} | "
                    f"{item.get('finding', 'Unknown Finding')} | "
                    f"Risk Score: {item.get('risk_score', 0)}"
                )
            )

            write_line(
                (
                    "Recommendation: "
                    f"{item.get('recommendation', 'Review and remediate per SLA.')}"
                ),
                indent=75,
                max_chars=95
            )

            y -= 5

    else:
        write_line(
            (
                "No client-specific remediation records are available yet. "
                "Run a new scan for this AWS account."
            )
        )

    y -= 12

    write_section(
        "Recommended Client Focus"
    )

    focus_areas = [
        "1. Review public-facing assets and validate business need.",
        "2. Address critical and high-risk remediation items.",
        "3. Validate IAM, MFA, and credential hygiene.",
        "4. Review Security Hub and GuardDuty findings.",
        "5. Run recurring scans and compare historical trends."
    ]

    for focus_area in focus_areas:
        write_line(
            focus_area
        )

    y -= 12

    write_section(
        "Assessment Notes"
    )

    notes = [
        (
            "This report is generated from saved DGS Sentinel AI platform data "
            "for the selected AWS account."
        ),
        (
            "The current assessment workflow is read-only. "
            "No AWS resources were modified."
        ),
        (
            "Remediation recommendations should be validated with the client "
            "before implementation."
        )
    ]

    for note in notes:
        write_line(
            note
        )

    add_footer()

    pdf.save()

    buffer.seek(
        0
    )

    return buffer
