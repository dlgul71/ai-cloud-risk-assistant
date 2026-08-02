from datetime import datetime, timedelta
from io import BytesIO
import hmac

import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from app_config import settings
from access_control import (
    PERMISSION_APPROVE_REMEDIATION,
    PERMISSION_EXECUTE_REMEDIATION,
    PERMISSION_MANAGE_CLIENTS,
    PERMISSION_RUN_SCANS,
    accessible_pages,
    has_permission,
    normalize_role,
)
from app_logging import configure_logging, get_logger
from health_checks import run_health_checks
from operational_monitoring import (
    SYSTEM_CLIENT_KEY,
    evaluate_health_alert,
    get_recent_health_runs,
    record_health_run,
    summarize_health_history,
)
from demo_mode import (
    demo_mode_enabled,
    sanitize_dataframe,
    sanitize_text,
    sanitize_value
)
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from risk_engine import (
    calculate_unified_risk,
    summarize_azure_findings,
)
from cloud_scan_routing import (
    build_azure_snapshot_assets,
    normalize_cloud_provider,
    summarize_azure_resources,
)
from scan_engine_phase3_assumerole import run_client_scan
from snapshot_engine import save_scan_snapshot
from kev_lookup import check_cve_in_kev, fetch_cisa_kev


configure_logging(settings.log_level)
logger = get_logger("dgs_sentinel.app")


# ============================================================
# OPTIONAL LOCAL MODULE IMPORTS
# ============================================================

try:
    from db import get_all_findings
except Exception:
    get_all_findings = None

try:
    from scan_engine import run_scan
except Exception:
    run_scan = None

try:
    from guardduty_ingest import get_guardduty_findings
except Exception:
    get_guardduty_findings = None

try:
    from org_ingest import get_organization_accounts
except Exception:
    get_organization_accounts = None

try:
    from client_db import (
        init_client_db,
        add_client,
        get_clients,
        get_client_key,
    )
except Exception:
    init_client_db = None
    add_client = None
    get_clients = None
    get_client_key = None

try:
    from azure_client_accounts import (
        create_azure_credential,
        test_azure_subscription,
    )
except Exception:
    create_azure_credential = None
    test_azure_subscription = None

try:
    from azure_resource_discovery import discover_azure_resources
except Exception:
    discover_azure_resources = None

try:
    from azure.mgmt.storage import StorageManagementClient
except Exception:
    StorageManagementClient = None

try:
    from azure.mgmt.network import NetworkManagementClient
except Exception:
    NetworkManagementClient = None

try:
    from azure_security_posture import discover_azure_security_posture
except Exception:
    discover_azure_security_posture = None

try:
    from azure_storage_exposure import analyze_storage_exposure
except Exception:
    analyze_storage_exposure = None

try:
    from remediation_execution import (
        create_actions_from_remediation_plan,
    )
except Exception:
    create_actions_from_remediation_plan = None

try:
    from azure_network_exposure import (
        analyze_azure_network_exposure,
    )
except Exception:
    analyze_azure_network_exposure = None

try:
    from azure_demo_data import build_azure_demo_dataset
except Exception:
    build_azure_demo_dataset = None

try:
    from streamlit_autorefresh import st_autorefresh
    AUTOREFRESH_AVAILABLE = True
except Exception:
    AUTOREFRESH_AVAILABLE = False


# ============================================================
# PAGE CONFIGURATION
# ============================================================


# Public Demo Mode display wrappers
# These sanitize visible content only. Database records remain unchanged.
_streamlit_dataframe = st.dataframe
_streamlit_json = st.json


def demo_dataframe(data, *args, **kwargs):
    try:
        safe_data = sanitize_dataframe(data)

    except Exception:
        safe_data = sanitize_value(data)

    return _streamlit_dataframe(
        safe_data,
        *args,
        **kwargs
    )


def demo_json(data, *args, **kwargs):
    return _streamlit_json(
        sanitize_value(data),
        *args,
        **kwargs
    )


_streamlit_write = st.write
_streamlit_markdown = st.markdown
_streamlit_info = st.info
_streamlit_success = st.success
_streamlit_warning = st.warning
_streamlit_caption = st.caption
_streamlit_download_button = st.download_button


def demo_download_button(*, label, data, file_name, mime=None, **kwargs):
    safe_data = data

    if demo_mode_enabled():
        if isinstance(data, bytes):
            try:
                safe_data = sanitize_text(
                    data.decode("utf-8")
                ).encode("utf-8")

            except UnicodeDecodeError:
                safe_data = data

        elif isinstance(data, str):
            safe_data = sanitize_text(data)

    return _streamlit_download_button(
        label=sanitize_text(label),
        data=safe_data,
        file_name=sanitize_text(file_name),
        mime=mime,
        **kwargs
    )




def demo_write(*args, **kwargs):
    return _streamlit_write(
        *[
            sanitize_value(value)
            for value in args
        ],
        **kwargs
    )


def demo_markdown(body, *args, **kwargs):
    return _streamlit_markdown(
        sanitize_text(body),
        *args,
        **kwargs
    )


def demo_info(body, *args, **kwargs):
    return _streamlit_info(
        sanitize_text(body),
        *args,
        **kwargs
    )


def demo_success(body, *args, **kwargs):
    return _streamlit_success(
        sanitize_text(body),
        *args,
        **kwargs
    )


def demo_warning(body, *args, **kwargs):
    return _streamlit_warning(
        sanitize_text(body),
        *args,
        **kwargs
    )


def demo_caption(body, *args, **kwargs):
    return _streamlit_caption(
        sanitize_text(body),
        *args,
        **kwargs
    )


st.set_page_config(
    page_title="DGS Sentinel AI",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

COMPANY_NAME = "Data Generated Solutions, LLC"
APP_NAME = "DGS Sentinel AI"


# ============================================================
# AUTHENTICATION
# ============================================================

def check_password():
    """Simple password authentication for DGS Sentinel AI."""

    session_timeout_minutes = settings.session_timeout_minutes

    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if "login_time" not in st.session_state:
        st.session_state["login_time"] = None

    if (
        st.session_state["authenticated"]
        and st.session_state["login_time"] is not None
    ):
        session_age = datetime.now() - st.session_state["login_time"]

        if session_age > timedelta(minutes=session_timeout_minutes):
            st.session_state["authenticated"] = False
            st.session_state["login_time"] = None
            demo_warning("Session expired. Please login again.")
            st.rerun()

    if st.session_state["authenticated"]:
        st.session_state["user_role"] = normalize_role(
            settings.app_role
        )
        return True

    st.title("🛡️ DGS Sentinel AI Login")
    demo_caption("Protected Cloud Security Analytics Platform")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login", type="primary"):
        try:
            correct_username = settings.app_username or ""
            correct_password = settings.app_password or ""
        except Exception:
            st.error("Authentication is not configured. Check .streamlit/secrets.toml.")
            return False

        if (
            hmac.compare_digest(username, correct_username)
            and hmac.compare_digest(password, correct_password)
        ):
            st.session_state["authenticated"] = True
            st.session_state["login_time"] = datetime.now()
            st.session_state["user_role"] = normalize_role(
                settings.app_role
            )
            st.rerun()
        else:
            st.error("Invalid username or password")

    return False


if not check_password():
    st.stop()


# ============================================================
# INITIALIZE CLIENT DATABASE
# ============================================================

if init_client_db is not None:
    try:
        init_client_db()
    except Exception as e:
        demo_warning(f"Client database could not be initialized: {e}")


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_get_findings():
    """Safely load saved findings from db.py."""
    if get_all_findings is None:
        return []

    try:
        return get_all_findings()
    except Exception as e:
        demo_warning(f"Unable to load saved findings: {e}")
        return []


def calculate_risk_rating(avg_risk):
    """Convert a numeric risk score to an executive risk rating."""
    if avg_risk >= 75:
        return "CRITICAL RISK"
    if avg_risk >= 50:
        return "HIGH RISK"
    if avg_risk >= 25:
        return "MODERATE RISK"
    return "LOW RISK"


def normalize_findings(rows):
    """Convert raw finding rows into a normalized DataFrame."""
    if not rows:
        return pd.DataFrame(
            columns=[
                "Scan Time",
                "CVE ID",
                "Priority",
                "Risk Score",
                "KEV Exploited",
                "Known Ransomware",
                "Required Action",
            ]
        )

    df = pd.DataFrame(
        rows,
        columns=[
            "Scan Time",
            "CVE ID",
            "Priority",
            "Risk Score",
            "KEV Exploited",
            "Known Ransomware",
            "Required Action",
        ]
    )

    df["Scan Time"] = pd.to_datetime(df["Scan Time"], errors="coerce")
    df = df.dropna(subset=["Scan Time"])

    if "Risk Score" in df.columns:
        df["Risk Score"] = pd.to_numeric(df["Risk Score"], errors="coerce").fillna(0)

    # Enrich findings with live CISA KEV intelligence
    try:
        kev_map = fetch_cisa_kev()

        if "CVE ID" in df.columns:
            df["KEV Exploited"] = df["CVE ID"].apply(
                lambda cve: 1 if cve in kev_map else 0
            )

            df["Known Ransomware"] = df["CVE ID"].apply(
                lambda cve: kev_map.get(cve, {}).get("known_ransomware", "Unknown")
            )

            df["Required Action"] = df["CVE ID"].apply(
                lambda cve: kev_map.get(cve, {}).get("required_action", "Review and remediate per SLA")
            )

            df.loc[df["KEV Exploited"] == 1, "Risk Score"] = (
                df["Risk Score"] + 20
            ).clip(upper=100)

            df.loc[df["KEV Exploited"] == 1, "Priority"] = "CRITICAL"

    except Exception as e:
        demo_warning(f"CISA KEV enrichment unavailable: {e}")

    return df


def generate_remediation_playbook(df):
    """Build a remediation playbook from findings."""
    playbook = []

    if df.empty:
        return playbook

    for _, row in df.iterrows():
        priority = row.get("Priority", "STANDARD")
        cve_id = row.get("CVE ID", "Unknown")
        risk_score = row.get("Risk Score", 0)
        kev = row.get("KEV Exploited", 0)

        if priority == "CRITICAL" or kev == 1:
            remediation_priority = "Immediate patching or isolation required"
            business_impact = "High exploitation likelihood and potential business disruption"
        elif priority == "HIGH":
            remediation_priority = "Remediate within standard SLA"
            business_impact = "Elevated exposure risk"
        else:
            remediation_priority = "Monitor and remediate during normal patch cycle"
            business_impact = "Lower immediate business impact"

        playbook.append(
            {
                "Priority": priority,
                "CVE ID": cve_id,
                "Risk Score": risk_score,
                "Remediation Priority": remediation_priority,
                "Business Impact": business_impact,
                "Required Action": row.get("Required Action", ""),
            }
        )

    return playbook


def build_mitre_mapping(df):
    """Map findings to MITRE ATT&CK style tactics and techniques."""
    mitre_rows = []

    if df.empty:
        return pd.DataFrame(
            columns=[
                "CVE ID",
                "Technique",
                "Tactic",
                "Priority",
                "Risk Score"
            ]
        )

    for _, row in df.iterrows():
        if row.get("KEV Exploited", 0) == 1:
            technique = "T1190 - Exploit Public-Facing Application"
            tactic = "Initial Access"
        else:
            technique = "T1595 - Active Scanning"
            tactic = "Reconnaissance"

        mitre_rows.append(
            {
                "CVE ID": row.get("CVE ID", "Unknown"),
                "Technique": technique,
                "Tactic": tactic,
                "Priority": row.get("Priority", "STANDARD"),
                "Risk Score": row.get("Risk Score", 0),
            }
        )

    return pd.DataFrame(mitre_rows)


def highlight_priority(row):
    """Highlight critical and high findings in tables."""
    priority = row.get("Priority", "")

    if priority == "CRITICAL":
        return ["background-color: #ffcccc"] * len(row)

    if priority == "HIGH":
        return ["background-color: #ffe0b3"] * len(row)

    return [""] * len(row)


def generate_risk_narrative(summary):
    """Generate a multi-cloud executive risk narrative."""
    risk_rating = summary.get(
        "Multi-Cloud Risk Rating",
        summary.get("Risk Rating", "UNKNOWN"),
    )
    risk_score = summary.get(
        "Multi-Cloud Risk Score",
        summary.get("Average Risk Score", 0),
    )
    critical = summary.get("Critical Findings", 0)
    kev = summary.get("KEV Exploited Findings", 0)
    azure_total = summary.get("Azure Total Findings", 0)

    return f"""
DGS Sentinel AI assessed the multi-cloud security posture and identified an
overall rating of {risk_rating} with a risk score of {risk_score}.

The environment currently shows {critical} AWS critical findings,
{kev} known exploited vulnerability indicators, and {azure_total}
Azure network and storage exposure findings.

Security leadership should prioritize exploited vulnerabilities,
internet-facing cloud resources, exposed management services, identity
controls, and tracked remediation across AWS and Azure.
"""


def generate_ai_analysis(summary, remediation_playbook):
    """Generate a deterministic multi-cloud executive analysis."""
    top_actions = remediation_playbook[:3]

    multi_cloud_rating = summary.get(
        "Multi-Cloud Risk Rating",
        summary.get("Risk Rating", "UNKNOWN"),
    )
    multi_cloud_score = summary.get(
        "Multi-Cloud Risk Score",
        summary.get("Average Risk Score", 0),
    )
    azure_total_findings = summary.get(
        "Azure Total Findings",
        0,
    )

    lines = [
        "Executive Analysis:",
        "",
        (
            "The current multi-cloud security risk posture is "
            f"classified as {multi_cloud_rating} with a risk "
            f"score of {multi_cloud_score}."
        ),
        (
            f"Azure contributes {azure_total_findings} network "
            "and storage exposure findings to the current posture."
        ),
        (
            "Priority should be given to findings that combine "
            "high exploitability, known exploitation intelligence, "
            "and public exposure."
        ),
        "",
        "Recommended Focus Areas:",
        "1. Remediate critical and KEV-associated vulnerabilities.",
        "2. Validate IAM MFA enforcement and stale credential exposure.",
        "3. Review GuardDuty and Security Hub findings for active threat indicators.",
        "4. Generate follow-up reports after remediation activity.",
        "",
        "Top Remediation Items:"
    ]

    if top_actions:
        for item in top_actions:
            lines.append(
                f"- {item.get('Priority', '')}: {item.get('CVE ID', '')} — {item.get('Remediation Priority', '')}"
            )
    else:
        lines.append("- No saved remediation items are currently available.")

    return "\n".join(lines)


def generate_pdf(ai_analysis, summary, remediation_playbook, risk_narrative="", asset_summary=None):
    """Generate a branded DGS Sentinel AI executive PDF report."""
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    width, height = letter

    def add_footer():
        pdf.setFont("Helvetica", 8)
        pdf.drawString(
            50,
            30,
            "Data Generated Solutions, LLC | DGS Sentinel AI Executive Cyber Risk Assessment"
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

    y = height - 60

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(50, y, "DGS Sentinel AI")

    y -= 25
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Executive Cyber Risk Assessment Report")

    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Prepared by: {COMPANY_NAME}")

    y -= 15
    pdf.drawString(
        50,
        y,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    y -= 35
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Executive Summary")

    y -= 18
    pdf.setFont("Helvetica", 9)

    intro_lines = [
        "DGS Sentinel AI provides executive-level visibility into cloud exposure, identity risk,",
        "threat intelligence, and remediation priorities across monitored cloud environments.",
        "This report summarizes key risk indicators, business impact areas, and recommended actions."
    ]

    for line in intro_lines:
        pdf.drawString(50, y, line)
        y -= 14

    y -= 20
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Executive Metrics")

    y -= 20
    pdf.setFont("Helvetica", 10)

    for key, value in summary.items():
        clean_key = str(key).replace("_", " ").title()
        pdf.drawString(65, y, f"{clean_key}: {value}")
        y -= 15

        if y < 80:
            y = new_page()
            pdf.setFont("Helvetica", 10)

    y -= 20

    if asset_summary:
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, "Asset & Client Exposure Summary")

        y -= 20
        pdf.setFont("Helvetica", 10)

        for key, value in asset_summary.items():
            clean_key = str(key).replace("_", " ").title()
            pdf.drawString(65, y, f"{clean_key}: {value}")
            y -= 15

            if y < 80:
                y = new_page()
                pdf.setFont("Helvetica", 10)

        y -= 20

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Risk Narrative")

    y -= 20
    pdf.setFont("Helvetica", 9)

    for line in risk_narrative.splitlines():
        clean_line = line.strip()

        if clean_line:
            pdf.drawString(65, y, clean_line[:110])
            y -= 14

            if y < 80:
                y = new_page()
                pdf.setFont("Helvetica", 9)

    y -= 20
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "Top Remediation Priorities")

    y -= 20
    pdf.setFont("Helvetica", 8)

    for item in remediation_playbook[:10]:
        line = (
            f"{item.get('Priority', '')} | "
            f"{item.get('CVE ID', item.get('Asset', ''))} | "
            f"{item.get('Remediation Priority', item.get('Issue', ''))} | "
            f"{item.get('Business Impact', '')}"
        )

        pdf.drawString(65, y, line[:115])
        y -= 14

        if y < 80:
            y = new_page()
            pdf.setFont("Helvetica", 8)

    y -= 20
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, y, "AI Executive Analysis")

    y -= 20
    pdf.setFont("Helvetica", 9)

    for line in ai_analysis.splitlines():
        clean_line = line.strip()

        if clean_line:
            pdf.drawString(65, y, clean_line[:110])
            y -= 14

            if y < 80:
                y = new_page()
                pdf.setFont("Helvetica", 9)

    add_footer()
    pdf.save()
    buffer.seek(0)

    return buffer


def generate_caasm_pdf(
    connector_mode,
    metrics,
    identity_governance_metrics,
    coverage_gap_metrics,
    policy_findings,
    coverage_gap_findings,
    executive_recommendations=None
):
    """Generate a client-ready executive CAASM assessment PDF."""
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    width, height = letter
    y = height - 60

    def add_footer():
        pdf.setFont("Helvetica", 8)
        pdf.drawString(
            50,
            30,
            "Data Generated Solutions, LLC | DGS Sentinel AI Executive CAASM Assessment"
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

        if y < 110:
            y = new_page()

        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, title)
        y -= 18
        pdf.setFont("Helvetica", 9)

    def write_key_value(key, value):
        nonlocal y

        if y < 80:
            y = new_page()
            pdf.setFont("Helvetica", 9)

        clean_key = str(key).replace("_", " ").title()
        pdf.drawString(65, y, f"{clean_key}: {value}")
        y -= 14

    def write_wrapped_line(line, indent=65, max_chars=105):
        nonlocal y

        clean_line = str(line).strip()

        while clean_line:
            if y < 80:
                y = new_page()
                pdf.setFont("Helvetica", 8)

            segment = clean_line[:max_chars]
            pdf.drawString(indent, y, segment)
            clean_line = clean_line[max_chars:]
            y -= 13

    pdf.setFont("Helvetica-Bold", 20)
    pdf.drawString(50, y, "DGS Sentinel AI")

    y -= 25
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, y, "Executive CAASM Assessment Report")

    y -= 18
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"Prepared by: {COMPANY_NAME}")

    y -= 14
    pdf.drawString(
        50,
        y,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    y -= 14
    pdf.drawString(
        50,
        y,
        f"Axonius Connector Mode: {connector_mode}"
    )

    y -= 30
    write_section("Executive CAASM Scorecard")

    for key, value in metrics.items():
        write_key_value(key, value)

    y -= 12
    write_section("Identity Governance Summary")

    for key, value in identity_governance_metrics.items():
        write_key_value(key, value)

    y -= 12
    write_section("Connector Coverage Summary")

    for key, value in coverage_gap_metrics.items():
        write_key_value(key, value)

    y -= 12
    write_section("Top CAASM Policy Findings")

    if policy_findings:
        for item in policy_findings[:10]:
            line = (
                f"{item.get('Priority', 'STANDARD')} | "
                f"{item.get('Category', 'Unknown')} | "
                f"{item.get('Finding', 'Unknown Finding')} | "
                f"Resource: {item.get('Resource', 'Unknown')}"
            )

            write_wrapped_line(line)

            recommendation = (
                f"Recommendation: "
                f"{item.get('Recommendation', 'Review and remediate per SLA.')}"
            )

            write_wrapped_line(recommendation, indent=75, max_chars=95)
            y -= 5

    else:
        write_wrapped_line("No CAASM policy findings detected.")

    y -= 12
    write_section("Connector Coverage Gaps")

    if coverage_gap_findings:
        for item in coverage_gap_findings[:10]:
            line = (
                f"{item.get('Priority', 'STANDARD')} | "
                f"{item.get('Source', 'Unknown Source')} | "
                f"Coverage: {item.get('Coverage %', 0)}% | "
                f"Connected: {item.get('Connected', False)}"
            )

            write_wrapped_line(line)

            recommendation = (
                f"Recommendation: "
                f"{item.get('Recommendation', 'Review connector coverage.')}"
            )

            write_wrapped_line(recommendation, indent=75, max_chars=95)
            y -= 5

    else:
        write_wrapped_line("No connector coverage gaps detected.")

    y -= 12
    write_section("Executive CAASM Recommendations")

    if executive_recommendations:
        for index, item in enumerate(
            executive_recommendations[:10],
            start=1
        ):
            line = (
                f"{index}. "
                f"{item.get('Priority', 'STANDARD')} | "
                f"{item.get('Category', 'Unknown')} | "
                f"{item.get('Recommendation', 'Review and remediate per SLA.')}"
            )

            write_wrapped_line(
                line,
                indent=65,
                max_chars=100
            )

            y -= 5

    else:
        fallback_priorities = [
            "1. Address orphaned and privileged accounts without MFA.",
            "2. Resolve unmanaged asset visibility gaps.",
            "3. Establish missing connector integrations.",
            "4. Review critical and high-risk CAASM findings.",
            "5. Validate improvements through recurring CAASM assessments."
        ]

        for priority in fallback_priorities:
            write_wrapped_line(priority)

    add_footer()
    pdf.save()
    buffer.seek(0)

    return buffer


def get_guardduty_data():
    """Safely load GuardDuty findings."""
    if get_guardduty_findings is None:
        return []

    try:
        return get_guardduty_findings()
    except Exception as e:
        demo_warning(f"GuardDuty data unavailable: {e}")
        return []


def get_organization_data():
    """Safely load AWS Organizations accounts."""
    if get_organization_accounts is None:
        return []

    try:
        return get_organization_accounts()
    except Exception:
        demo_info("AWS Organizations is not enabled or this account is not part of an organization.")
        return []


def get_basic_aws_identity():
    """Get current AWS identity if credentials are available."""
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()

        return {
            "Account": identity.get("Account", "Unknown"),
            "Arn": identity.get("Arn", "Unknown"),
            "UserId": identity.get("UserId", "Unknown"),
        }
    except Exception:
        return {
            "Account": "Unavailable",
            "Arn": "AWS credentials not configured",
            "UserId": "Unavailable",
        }

# ============================================================
# AWS ASSUME ROLE
# ============================================================

def assume_client_role(role_arn):
    """Assume AWS role for client account access."""

    try:
        sts = boto3.client("sts")

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="DGSSentinelAIScan"
        )

        creds = response["Credentials"]

        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )

        return session

    except Exception as e:
        st.error(f"AssumeRole failed: {e}")
        return None
# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

if demo_mode_enabled():
    demo_warning(
        "Public Demo Mode — Sample identifiers are displayed. "
        "Internal resource names and account identifiers are sanitized."
    )

with st.sidebar:

    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.session_state["login_time"] = None
        st.session_state.pop("user_role", None)
        st.rerun()

    st.caption(
        f"Role: {st.session_state.get('user_role', 'Viewer')}"
    )

    navigation_pages = accessible_pages(
        st.session_state.get("user_role"),
        [
            "Dashboard",
            "Executive Dashboard",
            "SOC Dashboard",
            "Risk Trends",
            "Remediation Center",
            "Execution Center",
            "Axonius CAASM Dashboard",
            "Ask Sentinel AI",
            "Client Accounts",
            "Client Security Dashboard",
            "Asset Dashboard",
            "System Health",
        ],
    )

    page = st.radio(
        "Navigation",
        navigation_pages,
        key="main_navigation"
    )
    st.sidebar.write("Selected page:", page)

    st.header("Configuration")

    enable_org_discovery = st.toggle(
        "Discover AWS Organization Accounts",
        value=False,
        help="Requires AWS Organizations permissions and a cross-account role.",
        key="toggle_org_discovery"
    )

    executive_mode = st.toggle(
        "Executive Summary Mode",
        value=False,
        help="Show a simplified board/client-ready view.",
        key="toggle_executive_mode"
    )

    auto_refresh = st.toggle(
        "Auto Refresh Dashboard",
        value=False,
        key="toggle_auto_refresh"
    )

    auto_scan_interval = st.selectbox(
        "Auto Refresh Interval",
        [
            "Off",
            "30 seconds",
            "1 minute",
            "5 minutes"
        ],
        index=0,
        key="auto_scan_interval_select"
    )


# ============================================================
# AUTO REFRESH
# ============================================================

if auto_refresh and AUTOREFRESH_AVAILABLE:
    interval_map = {
        "30 seconds": 30 * 1000,
        "1 minute": 60 * 1000,
        "5 minutes": 5 * 60 * 1000
    }

    interval = interval_map.get(auto_scan_interval, 0)

    if interval > 0:
        st_autorefresh(interval=interval, key="dashboard_refresh")


# ============================================================
# CLIENT ACCOUNTS PAGE
# ============================================================



if page == "SOC Dashboard":

    from asset_db import get_all_assets_admin
    from remediation_db import (
        get_all_remediation_items_admin,
    )
    import pandas as pd

    st.title("SOC Dashboard")
    demo_caption("Executive security operations overview")

    assets = get_all_assets_admin()
    remediation_items = (
        get_all_remediation_items_admin()
    )

    asset_count = len(assets)
    remediation_count = len(remediation_items)

    critical_remediation = 0
    open_remediation = 0
    overdue_remediation = 0
    avg_asset_risk = 0

    if assets:
        soc_asset_df = pd.DataFrame(
            assets,
            columns=[
                "Asset ID",
                "Asset Type",
                "Account ID",
                "Region",
                "Hostname",
                "Private IP",
                "Public IP",
                "State",
                "Risk Score",
                "Last Scan"
            ]
        )

        avg_asset_risk = round(soc_asset_df["Risk Score"].mean(), 2)

    if remediation_items:
        soc_remediation_df = pd.DataFrame(
            remediation_items,
            columns=[
                "ID",
                "Created At",
                "Category",
                "Priority",
                "Finding",
                "Recommendation",
                "Owner",
                "Status",
                "Risk Score",
                "Occurrence Count",
                "Last Seen At"
            ]
        )

        soc_remediation_df["Created At"] = pd.to_datetime(
            soc_remediation_df["Created At"],
            errors="coerce",
            utc=True
        )

        soc_remediation_df["Age (Days)"] = (
            pd.Timestamp.now(tz="UTC") - soc_remediation_df["Created At"]
        ).dt.days.fillna(0).astype(int)

        critical_remediation = len(
            soc_remediation_df[soc_remediation_df["Priority"] == "CRITICAL"]
        )

        open_remediation = len(
            soc_remediation_df[soc_remediation_df["Status"] == "Open"]
        )

        overdue_remediation = len(
            soc_remediation_df[soc_remediation_df["Age (Days)"] > 90]
        )

    soc_col1, soc_col2, soc_col3, soc_col4 = st.columns(4)

    soc_col1.metric("Total Assets", asset_count)
    soc_col2.metric("Average Asset Risk", avg_asset_risk)
    soc_col3.metric("Open Remediation", open_remediation)
    soc_col4.metric("Overdue Remediation", overdue_remediation)

    soc_col5, soc_col6 = st.columns(2)

    soc_col5.metric("Critical Remediation", critical_remediation)
    soc_col6.metric("Total Remediation Items", remediation_count)

    if assets:
        st.subheader("Top Risk Assets")

        top_soc_assets = soc_asset_df.sort_values(
            by="Risk Score",
            ascending=False
        ).head(10)

        demo_dataframe(
            top_soc_assets,
            width="stretch"
        )

    if remediation_items:
        st.subheader("Top Remediation Items")

        top_soc_remediation = soc_remediation_df.sort_values(
            by="Risk Score",
            ascending=False
        ).head(10)

        demo_dataframe(
            top_soc_remediation,
            width="stretch"
        )



if page == "Risk Trends":

    import json
    from pathlib import Path
    import pandas as pd

    st.title("Risk Trends")
    demo_caption("Historical risk trend analysis from saved scan snapshots")

    snapshot_dir = Path("scan_snapshots")
    trend_rows = []

    if snapshot_dir.exists():
        for snapshot_file in sorted(snapshot_dir.glob("*.json")):
            try:
                with open(snapshot_file, "r") as f:
                    data = json.load(f)

                summary_data = data.get("summary", {})

                trend_rows.append({
                    "Scan Time": data.get("scan_time"),
                    "Security Score": summary_data.get(
                        "security_score",
                        0,
                    ),
                    "Risk Rating": summary_data.get(
                        "risk_rating",
                        "UNKNOWN",
                    ),
                    "Multi-Cloud Security Score": summary_data.get(
                        "multi_cloud_security_score",
                        summary_data.get("security_score", 0),
                    ),
                    "Multi-Cloud Risk Score": summary_data.get(
                        "multi_cloud_risk_score",
                        0,
                    ),
                    "Multi-Cloud Risk Rating": summary_data.get(
                        "multi_cloud_risk_rating",
                        summary_data.get(
                            "risk_rating",
                            "UNKNOWN",
                        ),
                    ),
                    "Azure Critical Findings": summary_data.get(
                        "azure_critical_findings",
                        0,
                    ),
                    "Azure High Findings": summary_data.get(
                        "azure_high_findings",
                        0,
                    ),
                    "Azure Medium Findings": summary_data.get(
                        "azure_medium_findings",
                        0,
                    ),
                    "Azure Total Findings": summary_data.get(
                        "azure_total_findings",
                        0,
                    ),
                    "Assets": summary_data.get("assets", 0),
                    "EC2 Assets": summary_data.get("ec2_assets", 0),
                    "IAM Users": summary_data.get("iam_users", 0),
                    "S3 Buckets": summary_data.get("s3_buckets", 0),
                    "Security Hub Findings": summary_data.get("securityhub_findings", 0),
                    "GuardDuty Findings": summary_data.get("guardduty_findings", 0),
                    "KEV CVEs": summary_data.get("kev_cves", 0),
                    "Remediation Actions": summary_data.get("remediation_actions", 0),
                    "Critical Vulnerabilities": summary_data.get("critical_vulnerabilities", 0),
                    "Snapshot File": snapshot_file.name
                })

            except Exception as e:
                demo_warning(f"Unable to load snapshot {snapshot_file.name}: {e}")

    if trend_rows:
        trend_df = pd.DataFrame(trend_rows)
        trend_df["Scan Time"] = pd.to_datetime(trend_df["Scan Time"], errors="coerce")
        trend_df = trend_df.dropna(subset=["Scan Time"]).sort_values("Scan Time")

        latest = trend_df.iloc[-1]

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Latest Security Score", latest["Security Score"])
        col2.metric("Latest Risk Rating", latest["Risk Rating"])
        col3.metric("Latest Assets", latest["Assets"])
        col4.metric(
            "Latest Remediation Actions",
            latest["Remediation Actions"],
        )

        (
            multi_metric_col1,
            multi_metric_col2,
            multi_metric_col3,
            multi_metric_col4,
        ) = st.columns(4)

        multi_metric_col1.metric(
            "Multi-Cloud Security Score",
            latest["Multi-Cloud Security Score"],
        )
        multi_metric_col2.metric(
            "Multi-Cloud Risk Score",
            latest["Multi-Cloud Risk Score"],
        )
        multi_metric_col3.metric(
            "Multi-Cloud Rating",
            latest["Multi-Cloud Risk Rating"],
        )
        multi_metric_col4.metric(
            "Azure Findings",
            latest["Azure Total Findings"],
        )

        if len(trend_df) >= 2:
            previous = trend_df.iloc[-2]

            score_delta = latest["Security Score"] - previous["Security Score"]
            securityhub_delta = latest["Security Hub Findings"] - previous["Security Hub Findings"]
            guardduty_delta = latest["GuardDuty Findings"] - previous["GuardDuty Findings"]
            remediation_delta = (
                latest["Remediation Actions"]
                - previous["Remediation Actions"]
            )
            multi_cloud_risk_delta = (
                latest["Multi-Cloud Risk Score"]
                - previous["Multi-Cloud Risk Score"]
            )
            multi_cloud_security_delta = (
                latest["Multi-Cloud Security Score"]
                - previous["Multi-Cloud Security Score"]
            )
            azure_findings_delta = (
                latest["Azure Total Findings"]
                - previous["Azure Total Findings"]
            )

            st.subheader("Executive Risk Delta")

            delta_col1, delta_col2, delta_col3, delta_col4 = st.columns(4)

            delta_col1.metric(
                "Security Score Change",
                score_delta
            )

            delta_col2.metric(
                "Security Hub Findings Change",
                securityhub_delta
            )

            delta_col3.metric(
                "GuardDuty Findings Change",
                guardduty_delta
            )

            delta_col4.metric(
                "Remediation Actions Change",
                remediation_delta,
            )

            (
                multi_delta_col1,
                multi_delta_col2,
                multi_delta_col3,
            ) = st.columns(3)

            multi_delta_col1.metric(
                "Multi-Cloud Risk Change",
                multi_cloud_risk_delta,
            )
            multi_delta_col2.metric(
                "Multi-Cloud Security Change",
                multi_cloud_security_delta,
            )
            multi_delta_col3.metric(
                "Azure Findings Change",
                azure_findings_delta,
            )

        st.subheader("Security Score Over Time")
        st.line_chart(
            trend_df.set_index("Scan Time")["Security Score"]
        )

        st.subheader("Multi-Cloud Risk Over Time")
        st.line_chart(
            trend_df.set_index("Scan Time")[
                [
                    "Multi-Cloud Risk Score",
                    "Multi-Cloud Security Score",
                ]
            ]
        )

        st.subheader("Findings Trend")

        findings_trend = trend_df.set_index("Scan Time")[
            [
                "Security Hub Findings",
                "GuardDuty Findings",
                "Azure Total Findings",
                "KEV CVEs",
                "Critical Vulnerabilities"
            ]
        ]

        st.line_chart(findings_trend)

        st.subheader("Historical Snapshot Table")
        demo_dataframe(
            trend_df,
            width="stretch"
        )

        st.subheader("Snapshot Download Center")

        snapshot_files = sorted(
            snapshot_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )

        if snapshot_files:
            selected_snapshot = st.selectbox(
                "Select snapshot to download",
                [file.name for file in snapshot_files]
            )

            selected_snapshot_path = snapshot_dir / selected_snapshot

            with open(selected_snapshot_path, "rb") as snapshot_file:
                demo_download_button(
                    label="Download Selected Snapshot JSON",
                    data=snapshot_file,
                    file_name=selected_snapshot,
                    mime="application/json"
                )

            st.subheader("Snapshot Compare View")

            if len(snapshot_files) >= 2:
                latest_file = snapshot_files[0]
                previous_file = snapshot_files[1]

                with open(latest_file, "r") as f:
                    latest_snapshot = json.load(f)

                with open(previous_file, "r") as f:
                    previous_snapshot = json.load(f)

                latest_summary = latest_snapshot.get("summary", {})
                previous_summary = previous_snapshot.get("summary", {})

                compare_col1, compare_col2, compare_col3 = st.columns(3)

                compare_col1.metric(
                    "Security Score Delta",
                    latest_summary.get("security_score", 0) - previous_summary.get("security_score", 0)
                )

                compare_col2.metric(
                    "Assets Delta",
                    latest_summary.get("assets", 0) - previous_summary.get("assets", 0)
                )

                compare_col3.metric(
                    "Remediation Delta",
                    latest_summary.get("remediation_actions", 0) - previous_summary.get("remediation_actions", 0)
                )

                compare_col4, compare_col5 = st.columns(2)

                compare_col4.metric(
                    "Security Hub Findings Delta",
                    latest_summary.get("securityhub_findings", 0) - previous_summary.get("securityhub_findings", 0)
                )

                compare_col5.metric(
                    "GuardDuty Findings Delta",
                    latest_summary.get(
                        "guardduty_findings",
                        0,
                    )
                    - previous_summary.get(
                        "guardduty_findings",
                        0,
                    ),
                )

                (
                    compare_multi_col1,
                    compare_multi_col2,
                ) = st.columns(2)

                compare_multi_col1.metric(
                    "Multi-Cloud Risk Delta",
                    latest_summary.get(
                        "multi_cloud_risk_score",
                        0,
                    )
                    - previous_summary.get(
                        "multi_cloud_risk_score",
                        0,
                    ),
                )

                compare_multi_col2.metric(
                    "Azure Findings Delta",
                    latest_summary.get(
                        "azure_total_findings",
                        0,
                    )
                    - previous_summary.get(
                        "azure_total_findings",
                        0,
                    ),
                )

                demo_caption(
                    f"Comparing latest snapshot {latest_file.name} against previous snapshot {previous_file.name}."
                )
            else:
                demo_info("At least two snapshots are required for comparison.")

    else:
        demo_info("No scan snapshots found yet. Run scans to build historical trend data.")


if page == "Executive Dashboard":

    from client_db import get_clients
    from asset_db import get_all_assets_admin
    import pandas as pd

    st.title("Executive Dashboard")
    demo_caption("Multi-client executive risk overview")

    clients = get_clients()
    assets = get_all_assets_admin()

    total_clients = len(clients)
    total_assets = len(assets)

    if assets:
        asset_df = pd.DataFrame(
            assets,
            columns=[
                "Asset ID",
                "Asset Type",
                "Account ID",
                "Region",
                "Hostname",
                "Private IP",
                "Public IP",
                "State",
                "Risk Score",
                "Last Scan"
            ]
        )

        avg_risk = round(asset_df["Risk Score"].mean(), 2)
        critical_assets = len(asset_df[asset_df["Risk Score"] >= 80])

    else:
        avg_risk = 0
        critical_assets = 0

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Clients", total_clients)
    col2.metric("Assets", total_assets)
    col3.metric("Average Risk", avg_risk)
    col4.metric("Critical Assets", critical_assets)

    if assets:
        st.subheader("Highest Risk Assets")

        top_assets = asset_df.sort_values(
            by="Risk Score",
            ascending=False
        ).head(10)

        demo_dataframe(
            top_assets,
            width="stretch"
        )

        st.subheader("Client Risk Ranking")

        client_lookup = {
            str(client[2]): client[1]
            for client in clients
        }

        client_risk_df = (
            asset_df.groupby("Account ID")
            .agg(
                Assets=("Asset ID", "count"),
                Average_Risk=("Risk Score", "mean"),
                Critical_Assets=("Risk Score", lambda x: (x >= 80).sum()),
                Public_Assets=("Public IP", lambda x: x.notna().sum())
            )
            .reset_index()
        )

        client_risk_df["Client Name"] = client_risk_df["Account ID"].map(
            client_lookup
        ).fillna("Unknown Client")

        client_risk_df["Average_Risk"] = client_risk_df["Average_Risk"].round(2)

        client_risk_df = client_risk_df[
            [
                "Client Name",
                "Account ID",
                "Assets",
                "Average_Risk",
                "Critical_Assets",
                "Public_Assets"
            ]
        ].sort_values(
            by="Average_Risk",
            ascending=False
        )

        demo_dataframe(
            client_risk_df,
            width="stretch"
        )




if page == "System Health":
    st.title("System Health")

    demo_caption(
        "Production readiness, configuration, storage, "
        "database, dependency, AWS identity, Splunk HEC, "
        "and Axonius connectivity checks."
    )

    include_aws_health_check = st.checkbox(
        "Include AWS STS identity check",
        value=False,
        help=(
            "Performs a read-only AWS identity request "
            "using the current credential chain."
        )
    )

    include_splunk_health_check = st.checkbox(
        "Include Splunk HEC connectivity check",
        value=False,
        help=(
            "Sends a clearly identified platform-health "
            "test event to the configured Splunk HEC endpoint."
        )
    )

    include_axonius_health_check = st.checkbox(
        "Include Axonius connectivity check",
        value=False,
        help=(
            "Performs a read-only Axonius asset API request "
            "using the configured connector credentials."
        )
    )

    if st.button(
        "Run Health Checks",
        type="primary"
    ):
        with st.spinner(
            "Running production health checks..."
        ):
            health_payload = run_health_checks(
                include_aws=include_aws_health_check,
                include_splunk=include_splunk_health_check,
                include_axonius=include_axonius_health_check,
            )

            monitoring_record = record_health_run(
                health_payload,
                client_key=SYSTEM_CLIENT_KEY,
                source="streamlit-system-health",
            )

            health_payload["monitoring_record"] = (
                monitoring_record
            )
            health_payload["operational_alert"] = (
                evaluate_health_alert(
                    health_payload
                )
            )

            st.session_state[
                "system_health_results"
            ] = health_payload

    health_results = st.session_state.get(
        "system_health_results"
    )

    if not health_results:
        demo_info(
            "Select the desired checks and click "
            "Run Health Checks."
        )
        st.stop()

    overall_status = health_results.get(
        "overall_status",
        "UNKNOWN"
    )

    column1, column2, column3, column4 = (
        st.columns(4)
    )

    column1.metric(
        "Overall Status",
        overall_status
    )

    column2.metric(
        "Passed",
        health_results.get("pass_count", 0)
    )

    column3.metric(
        "Warnings",
        health_results.get(
            "warning_count",
            0
        )
    )

    column4.metric(
        "Failed",
        health_results.get("fail_count", 0)
    )

    if overall_status == "PASS":
        demo_success(
            "All selected production health checks passed."
        )

    elif overall_status == "WARN":
        demo_warning(
            "Health checks completed with warnings."
        )

    else:
        st.error(
            "One or more production health checks failed."
        )

    operational_alert = health_results.get(
        "operational_alert"
    ) or evaluate_health_alert(
        health_results
    )

    alert_level = operational_alert.get(
        "level",
        "UNKNOWN",
    )
    alert_message = operational_alert.get(
        "message",
        "Operational alert status unavailable.",
    )

    if alert_level == "CRITICAL":
        st.error(
            f"Operational Alert: {alert_message}"
        )
    elif alert_level == "WARNING":
        demo_warning(
            f"Operational Alert: {alert_message}"
        )
    else:
        demo_success(
            f"Operational Status: {alert_message}"
        )

    monitoring_record = health_results.get(
        "monitoring_record",
        {},
    )

    if monitoring_record:
        demo_caption(
            "Monitoring record ID: "
            f"{monitoring_record.get('run_id', 'Unknown')}"
        )

    health_history_summary = (
        summarize_health_history(
            client_key=SYSTEM_CLIENT_KEY,
            limit=100,
        )
    )
    recent_health_runs = get_recent_health_runs(
        client_key=SYSTEM_CLIENT_KEY,
        limit=10,
    )

    st.subheader("Operational Monitoring History")

    history_column1, history_column2, history_column3, (
        history_column4
    ) = st.columns(4)

    history_column1.metric(
        "Recorded Runs",
        health_history_summary.get(
            "total_runs",
            0,
        ),
    )
    pass_rate_percent = health_history_summary.get(
        "pass_rate_percent",
        0.0,
    )

    history_column2.metric(
        "Pass Rate",
        f"{pass_rate_percent}%",
    )
    history_column3.metric(
        "Warning Runs",
        health_history_summary.get(
            "warning_runs",
            0,
        ),
    )
    history_column4.metric(
        "Failed Runs",
        health_history_summary.get(
            "failed_runs",
            0,
        ),
    )

    if recent_health_runs:
        demo_dataframe(
            recent_health_runs,
            width="stretch",
            hide_index=True,
        )

    demo_caption(
        "Checked at: "
        f"{health_results.get('checked_at', 'Unknown')}"
    )

    demo_dataframe(
        health_results.get("checks", []),
        width="stretch",
        hide_index=True
    )

    st.stop()


if page == "Client Security Dashboard":

    from client_db import get_clients
    from asset_db import get_assets
    from remediation_db import get_remediation_items_with_client_context
    from client_detection_store import load_client_scan_summary
    import pandas as pd

    st.title("Client Security Dashboard")
    demo_caption(
        "Selected-client AWS security posture, asset exposure, "
        "risk prioritization, and service coverage."
    )

    clients = get_clients() if get_clients is not None else []
    assets = []

    if not clients:
        demo_info(
            "No saved client accounts were found. "
            "Add a client from the Client Accounts page first."
        )

    else:
        client_options = {}

        for client in clients:
            client_id = client[0]
            client_name = client[1]
            aws_account_id = client[2]
            environment = client[4]

            display_label = sanitize_text(
                f"{client_name} | {aws_account_id} | {environment}"
            )

            client_options[display_label] = client

        selected_client_label = st.selectbox(
            "Select Client",
            list(client_options.keys()),
            key="client_security_dashboard_selector"
        )

        selected_client = client_options[selected_client_label]

        client_id = selected_client[0]

        if get_client_key is None:
            raise RuntimeError(
                "Client tenant-key lookup is unavailable."
            )

        client_key = get_client_key(client_id)

        if not client_key:
            raise RuntimeError(
                "The selected client does not have a tenant key."
            )

        assets = get_assets(client_key)
        client_name = selected_client[1]
        aws_account_id = selected_client[2]
        role_arn = selected_client[3]
        environment = selected_client[4]

        display_client_name = sanitize_text(client_name)
        display_account_id = sanitize_text(aws_account_id)

        demo_info(
            f"Active Client: {display_client_name} | "
            f"AWS Account: {display_account_id} | "
            f"Environment: {environment}"
        )

        asset_columns = [
            "Asset ID",
            "Asset Type",
            "Account ID",
            "Region",
            "Hostname",
            "Private IP",
            "Public IP",
            "State",
            "Risk Score",
            "Last Scan"
        ]

        if assets:
            all_asset_df = pd.DataFrame(
                assets,
                columns=asset_columns
            )

            all_asset_df["Account ID"] = (
                all_asset_df["Account ID"]
                .astype(str)
            )

            all_asset_df["Risk Score"] = pd.to_numeric(
                all_asset_df["Risk Score"],
                errors="coerce"
            ).fillna(0)

            client_asset_df = all_asset_df[
                all_asset_df["Account ID"] == str(aws_account_id)
            ].copy()

        else:
            client_asset_df = pd.DataFrame(columns=asset_columns)

        total_assets = len(client_asset_df)

        average_risk = (
            round(client_asset_df["Risk Score"].mean(), 2)
            if total_assets
            else 0
        )

        critical_assets = (
            int((client_asset_df["Risk Score"] >= 80).sum())
            if total_assets
            else 0
        )

        high_assets = (
            int(
                (
                    (client_asset_df["Risk Score"] >= 60)
                    & (client_asset_df["Risk Score"] < 80)
                ).sum()
            )
            if total_assets
            else 0
        )

        if total_assets:
            public_ip_values = (
                client_asset_df["Public IP"]
                .fillna("")
                .astype(str)
                .str.strip()
                .str.lower()
            )

            public_assets = int(
                (~public_ip_values.isin(
                    ["", "none", "null", "n/a", "nan"]
                )).sum()
            )

            last_scan_values = (
                client_asset_df["Last Scan"]
                .dropna()
                .astype(str)
            )

            last_scan = (
                last_scan_values.max()
                if not last_scan_values.empty
                else "No scan recorded"
            )

        else:
            public_assets = 0
            last_scan = "No scan recorded"

        if last_scan != "No scan recorded":
            parsed_last_scan = pd.to_datetime(
                last_scan,
                errors="coerce",
                utc=True
            )

            if pd.notna(parsed_last_scan):
                last_scan_display = (
                    parsed_last_scan
                    .tz_convert("America/Chicago")
                    .strftime("%b %d, %Y %I:%M %p CT")
                )
            else:
                last_scan_display = str(last_scan)

        else:
            last_scan_display = last_scan

        connection_status = (
            "Configured"
            if role_arn
            else "Role not configured"
        )

        st.subheader("Client Security Summary")

        summary_col1, summary_col2, summary_col3, summary_col4 = st.columns(4)

        summary_col1.metric(
            "Total Assets",
            total_assets
        )

        summary_col2.metric(
            "Average Asset Risk",
            average_risk
        )

        summary_col3.metric(
            "Critical Assets",
            critical_assets
        )

        summary_col4.metric(
            "Public Assets",
            public_assets
        )

        summary_col5, summary_col6, summary_col7, summary_col8 = st.columns(4)

        summary_col5.metric(
            "High-Risk Assets",
            high_assets
        )

        summary_col6.metric(
            "Connection",
            connection_status
        )

        summary_col7.metric(
            "Environment",
            environment or "Not specified"
        )

        summary_col8.metric(
            "Last Scan",
            last_scan_display
        )

        st.subheader("AWS Service Coverage")

        def service_metrics(service_name, aliases):
            if client_asset_df.empty:
                return {
                    "Service": service_name,
                    "Status": "No assets discovered",
                    "Resources": 0,
                    "Critical": 0,
                    "High": 0
                }

            asset_types = (
                client_asset_df["Asset Type"]
                .fillna("")
                .astype(str)
                .str.lower()
            )

            service_mask = asset_types.apply(
                lambda value: any(
                    alias in value
                    for alias in aliases
                )
            )

            service_assets = client_asset_df[service_mask]

            resource_count = len(service_assets)

            return {
                "Service": service_name,
                "Status": (
                    "Data available"
                    if resource_count
                    else "No assets discovered"
                ),
                "Resources": resource_count,
                "Critical": int(
                    (service_assets["Risk Score"] >= 80).sum()
                ) if resource_count else 0,
                "High": int(
                    (
                        (service_assets["Risk Score"] >= 60)
                        & (service_assets["Risk Score"] < 80)
                    ).sum()
                ) if resource_count else 0
            }

        latest_service_summary = (
            load_client_scan_summary(
                aws_account_id
            )
        )

        service_rows = [
            service_metrics(
                "EC2",
                ["ec2", "instance"]
            ),
            service_metrics(
                "IAM",
                ["iam", "user", "role", "identity"]
            ),
            service_metrics(
                "S3",
                ["s3", "bucket"]
            ),
            {
                "Service": "Security Hub",
                "Status": latest_service_summary.get(
                    "securityhub_status",
                    "No scan recorded"
                ),
                "Resources": latest_service_summary.get(
                    "securityhub_count",
                    0
                ),
                "Critical": latest_service_summary.get(
                    "securityhub_critical",
                    0
                ),
                "High": latest_service_summary.get(
                    "securityhub_high",
                    0
                )
            },
            {
                "Service": "GuardDuty",
                "Status": latest_service_summary.get(
                    "guardduty_status",
                    "No scan recorded"
                ),
                "Resources": latest_service_summary.get(
                    "guardduty_count",
                    0
                ),
                "Critical": latest_service_summary.get(
                    "guardduty_critical",
                    0
                ),
                "High": latest_service_summary.get(
                    "guardduty_high",
                    0
                )
            },
            {
                "Service": "AWS Config",
                "Status": latest_service_summary.get(
                    "config_status",
                    "No scan recorded"
                ),
                "Resources": latest_service_summary.get(
                    "config_noncompliant_resource_count",
                    0
                ),
                "Critical": latest_service_summary.get(
                    "config_critical",
                    0
                ),
                "High": latest_service_summary.get(
                    "config_high",
                    0
                )
            }
        ]

        service_df = pd.DataFrame(service_rows)

        demo_dataframe(
            service_df,
            width="stretch",
            hide_index=True
        )

        st.subheader("Client Asset Risk")

        if client_asset_df.empty:
            demo_info(
                "No saved assets currently match this client's AWS account ID. "
                "Run a client scan to populate this dashboard."
            )

        else:
            risk_display_df = client_asset_df.sort_values(
                by="Risk Score",
                ascending=False
            ).copy()

            risk_display_df["Account ID"] = (
                risk_display_df["Account ID"]
                .astype(str)
                .apply(sanitize_text)
            )

            demo_dataframe(
                risk_display_df,
                width="stretch",
                hide_index=True
            )


        st.subheader("Client Remediation Queue")

        remediation_rows = (
            get_remediation_items_with_client_context(
                client_key
            )
        )

        remediation_columns = [
            "ID",
            "Created At",
            "Category",
            "Priority",
            "Finding",
            "Recommendation",
            "Owner",
            "Status",
            "Risk Score",
            "Occurrence Count",
            "Last Seen At",
            "AWS Account ID",
            "Client Name"
        ]

        if remediation_rows:
            all_remediation_df = pd.DataFrame(
                remediation_rows,
                columns=remediation_columns
            )

            all_remediation_df["AWS Account ID"] = (
                all_remediation_df["AWS Account ID"]
                .fillna("")
                .astype(str)
            )

            all_remediation_df["Client Name"] = (
                all_remediation_df["Client Name"]
                .fillna("")
                .astype(str)
            )

            account_match = (
                all_remediation_df["AWS Account ID"]
                == str(aws_account_id)
            )

            client_name_match = (
                all_remediation_df["Client Name"]
                .str.casefold()
                == str(client_name).casefold()
            )

            client_remediation_df = all_remediation_df[
                account_match | client_name_match
            ].copy()

        else:
            client_remediation_df = pd.DataFrame(
                columns=remediation_columns
            )

        if client_remediation_df.empty:
            demo_info(
                "No remediation findings currently match this client. "
                "Run a client assessment to populate the remediation queue."
            )

        else:
            client_remediation_df["Risk Score"] = pd.to_numeric(
                client_remediation_df["Risk Score"],
                errors="coerce"
            ).fillna(0)

            client_remediation_df["Occurrence Count"] = pd.to_numeric(
                client_remediation_df["Occurrence Count"],
                errors="coerce"
            ).fillna(1).astype(int)

            normalized_status = (
                client_remediation_df["Status"]
                .fillna("Open")
                .astype(str)
                .str.strip()
                .str.lower()
            )

            closed_statuses = [
                "closed",
                "resolved",
                "completed"
            ]

            open_mask = ~normalized_status.isin(closed_statuses)

            open_remediation_df = client_remediation_df[
                open_mask
            ].copy()

            open_priority = (
                open_remediation_df["Priority"]
                .fillna("")
                .astype(str)
                .str.strip()
                .str.upper()
            )

            open_items = len(open_remediation_df)

            critical_items = int(
                (open_priority == "CRITICAL").sum()
            )

            high_items = int(
                (open_priority == "HIGH").sum()
            )

            persistent_items = int(
                (
                    open_remediation_df["Occurrence Count"] > 1
                ).sum()
            )

            remediation_col1, remediation_col2, remediation_col3, remediation_col4 = (
                st.columns(4)
            )

            remediation_col1.metric(
                "Open Findings",
                open_items
            )

            remediation_col2.metric(
                "Critical Open",
                critical_items
            )

            remediation_col3.metric(
                "High Open",
                high_items
            )

            remediation_col4.metric(
                "Persistent Findings",
                persistent_items
            )

            queue_display_columns = [
                "Priority",
                "Category",
                "Finding",
                "Recommendation",
                "Owner",
                "Status",
                "Risk Score",
                "Occurrence Count",
                "Last Seen At"
            ]

            queue_display_df = (
                client_remediation_df[
                    queue_display_columns
                ]
                .sort_values(
                    by=[
                        "Risk Score",
                        "Occurrence Count"
                    ],
                    ascending=[
                        False,
                        False
                    ]
                )
            )

            demo_dataframe(
                queue_display_df,
                width="stretch",
                hide_index=True
            )

            safe_client_file_name = (
                sanitize_text(client_name)
                .lower()
                .replace(" ", "_")
                .replace("/", "_")
            )

            remediation_csv = (
                queue_display_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Client Remediation Queue CSV",
                data=remediation_csv,
                file_name=(
                    f"dgs_sentinel_{safe_client_file_name}"
                    "_remediation_queue.csv"
                ),
                mime="text/csv"
            )


        st.subheader("Client Risk Trend Since Previous Scan")

        import json
        from pathlib import Path

        client_snapshot_dir = Path("scan_snapshots")
        client_trend_rows = []

        def safe_numeric_risk(value):
            try:
                return float(value or 0)
            except (TypeError, ValueError):
                return 0.0

        if client_snapshot_dir.exists():
            for client_snapshot_file in sorted(
                client_snapshot_dir.glob("*.json")
            ):
                try:
                    with open(
                        client_snapshot_file,
                        "r"
                    ) as snapshot_handle:
                        snapshot_data = json.load(snapshot_handle)

                    snapshot_assets = snapshot_data.get(
                        "assets",
                        []
                    )

                    matching_snapshot_assets = [
                        asset
                        for asset in snapshot_assets
                        if str(
                            asset.get("account_id", "")
                        ) == str(aws_account_id)
                    ]

                    # Only include snapshots containing this account.
                    if not matching_snapshot_assets:
                        continue

                    snapshot_risk_scores = [
                        safe_numeric_risk(
                            asset.get("risk_score", 0)
                        )
                        for asset in matching_snapshot_assets
                    ]

                    snapshot_asset_count = len(
                        matching_snapshot_assets
                    )

                    snapshot_average_risk = (
                        round(
                            sum(snapshot_risk_scores)
                            / len(snapshot_risk_scores),
                            2
                        )
                        if snapshot_risk_scores
                        else 0
                    )

                    snapshot_critical_assets = sum(
                        score >= 80
                        for score in snapshot_risk_scores
                    )

                    snapshot_high_assets = sum(
                        60 <= score < 80
                        for score in snapshot_risk_scores
                    )

                    snapshot_public_assets = 0

                    for snapshot_asset in matching_snapshot_assets:
                        snapshot_public_ip = str(
                            snapshot_asset.get(
                                "public_ip",
                                ""
                            )
                            or ""
                        ).strip().lower()

                        if snapshot_public_ip not in [
                            "",
                            "none",
                            "null",
                            "n/a",
                            "nan"
                        ]:
                            snapshot_public_assets += 1

                    snapshot_security_score = round(
                        max(
                            0,
                            100 - snapshot_average_risk
                        ),
                        2
                    )

                    client_trend_rows.append({
                        "Scan Time": snapshot_data.get(
                            "scan_time"
                        ),
                        "Average Risk": snapshot_average_risk,
                        "Security Score": snapshot_security_score,
                        "Assets": snapshot_asset_count,
                        "Critical Assets": snapshot_critical_assets,
                        "High-Risk Assets": snapshot_high_assets,
                        "Public Assets": snapshot_public_assets,
                        "Snapshot File": client_snapshot_file.name
                    })

                except Exception as snapshot_error:
                    demo_warning(
                        f"Unable to process client snapshot "
                        f"{client_snapshot_file.name}: "
                        f"{snapshot_error}"
                    )

        if client_trend_rows:
            client_trend_df = pd.DataFrame(
                client_trend_rows
            )

            client_trend_df["Scan Time"] = pd.to_datetime(
                client_trend_df["Scan Time"],
                errors="coerce"
            )

            client_trend_df = (
                client_trend_df
                .dropna(subset=["Scan Time"])
                .sort_values("Scan Time")
                .drop_duplicates(
                    subset=["Scan Time"],
                    keep="last"
                )
            )

            if client_trend_df.empty:
                demo_info(
                    "Client snapshots were found, but their scan "
                    "timestamps could not be processed."
                )

            else:
                latest_client_snapshot = (
                    client_trend_df.iloc[-1]
                )

                previous_client_snapshot = (
                    client_trend_df.iloc[-2]
                    if len(client_trend_df) >= 2
                    else None
                )

                current_average_risk = round(
                    float(
                        latest_client_snapshot[
                            "Average Risk"
                        ]
                    ),
                    2
                )

                current_asset_count = int(
                    latest_client_snapshot["Assets"]
                )

                current_critical_assets = int(
                    latest_client_snapshot[
                        "Critical Assets"
                    ]
                )

                current_public_assets = int(
                    latest_client_snapshot[
                        "Public Assets"
                    ]
                )

                if previous_client_snapshot is not None:
                    previous_average_risk = round(
                        float(
                            previous_client_snapshot[
                                "Average Risk"
                            ]
                        ),
                        2
                    )

                    risk_change = round(
                        current_average_risk
                        - previous_average_risk,
                        2
                    )

                    asset_change = (
                        current_asset_count
                        - int(
                            previous_client_snapshot[
                                "Assets"
                            ]
                        )
                    )

                    critical_change = (
                        current_critical_assets
                        - int(
                            previous_client_snapshot[
                                "Critical Assets"
                            ]
                        )
                    )

                    public_change = (
                        current_public_assets
                        - int(
                            previous_client_snapshot[
                                "Public Assets"
                            ]
                        )
                    )

                    if risk_change < 0:
                        trend_status = "Improving"
                    elif risk_change > 0:
                        trend_status = "Worsening"
                    else:
                        trend_status = "Stable"

                else:
                    previous_average_risk = "N/A"
                    risk_change = "N/A"
                    asset_change = "N/A"
                    critical_change = "N/A"
                    public_change = "N/A"
                    trend_status = "Baseline"

                trend_col1, trend_col2, trend_col3, trend_col4 = (
                    st.columns(4)
                )

                trend_col1.metric(
                    "Current Average Risk",
                    current_average_risk
                )

                trend_col2.metric(
                    "Previous Average Risk",
                    previous_average_risk
                )

                trend_col3.metric(
                    "Risk Change",
                    risk_change
                )

                trend_col4.metric(
                    "Trend Status",
                    trend_status
                )

                change_col1, change_col2, change_col3, change_col4 = (
                    st.columns(4)
                )

                change_col1.metric(
                    "Asset Count Change",
                    asset_change
                )

                change_col2.metric(
                    "Critical Asset Change",
                    critical_change
                )

                change_col3.metric(
                    "Public Asset Change",
                    public_change
                )

                change_col4.metric(
                    "Client Snapshots",
                    len(client_trend_df)
                )

                st.markdown("#### Average Risk Over Time")

                st.line_chart(
                    client_trend_df.set_index(
                        "Scan Time"
                    )["Average Risk"]
                )

                st.markdown("#### Client Snapshot History")

                client_trend_display_df = (
                    client_trend_df[
                        [
                            "Scan Time",
                            "Average Risk",
                            "Security Score",
                            "Assets",
                            "Critical Assets",
                            "High-Risk Assets",
                            "Public Assets"
                        ]
                    ]
                    .sort_values(
                        "Scan Time",
                        ascending=False
                    )
                )

                demo_dataframe(
                    client_trend_display_df,
                    width="stretch",
                    hide_index=True
                )

                trend_safe_client_name = (
                    sanitize_text(client_name)
                    .lower()
                    .replace(" ", "_")
                    .replace("/", "_")
                )

                client_trend_csv = (
                    client_trend_display_df
                    .to_csv(index=False)
                    .encode("utf-8")
                )

                demo_download_button(
                    label="Download Client Risk Trend CSV",
                    data=client_trend_csv,
                    file_name=(
                        f"dgs_sentinel_{trend_safe_client_name}"
                        "_risk_trend.csv"
                    ),
                    mime="text/csv"
                )

                if len(client_trend_df) < 2:
                    demo_info(
                        "This is the client's baseline snapshot. "
                        "Run another client scan to calculate risk changes."
                    )

                demo_caption(
                    "Only snapshots containing assets for the selected "
                    "AWS account are included in this client trend."
                )

        else:
            demo_info(
                "No historical snapshots contain assets for this "
                "client account. Run a client scan to establish a baseline."
            )


        st.subheader("Client Security Report")

        from client_analyst_report import (
            generate_client_analyst_pdf
        )

        client_security_pdf = generate_client_analyst_pdf(
            client_name=client_name,
            aws_account_id=aws_account_id
        )

        report_safe_client_name = (
            sanitize_text(client_name)
            .lower()
            .replace(" ", "_")
            .replace("/", "_")
        )

        demo_download_button(
            label="Download Client Security Report PDF",
            data=client_security_pdf,
            file_name=(
                f"dgs_sentinel_{report_safe_client_name}"
                "_security_report.pdf"
            ),
            mime="application/pdf"
        )

        demo_caption(
            "This report is generated from saved read-only assessment "
            "data for the selected AWS account. It includes executive "
            "metrics, remediation priorities, and recommended focus areas."
        )


if page == "Asset Dashboard":

    from asset_db import get_all_assets_admin
    import pandas as pd

    st.title("Asset Dashboard")
    demo_caption("CAASM-style asset inventory for client AWS assets")

    assets = get_all_assets_admin()

    columns = [
        "Asset ID",
        "Asset Type",
        "Account ID",
        "Region",
        "Hostname",
        "Private IP",
        "Public IP",
        "State",
        "Risk Score",
        "Last Scan"
    ]

    if assets:
        asset_df = pd.DataFrame(assets, columns=columns)

        total_assets = len(asset_df)
        avg_asset_risk = round(asset_df["Risk Score"].mean(), 2)
        critical_assets = len(asset_df[asset_df["Risk Score"] >= 80])
        public_assets = len(asset_df[asset_df["Public IP"].notna() & (asset_df["Public IP"] != "")])

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Assets", total_assets)
        col2.metric("Average Risk", avg_asset_risk)
        col3.metric("Critical Assets", critical_assets)
        col4.metric("Public Assets", public_assets)

        st.subheader("Cloud Asset Inventory")

        asset_df = asset_df.sort_values(
            by="Risk Score",
            ascending=False
        )

        demo_dataframe(
            asset_df,
            width='stretch'
        )

        st.subheader("Risk Distribution")

        risk_chart_df = asset_df.copy()

        st.bar_chart(
            risk_chart_df.set_index("Asset ID")["Risk Score"]
        )

        st.subheader("Exposure Analytics")

        public_assets = len(
            asset_df[
                asset_df["Public IP"].notna() &
                (asset_df["Public IP"] != "")
            ]
        )

        stopped_assets = len(
            asset_df[
                asset_df["State"] == "stopped"
            ]
        )

        exp_col1, exp_col2 = st.columns(2)

        exp_col1.metric("Public Assets", public_assets)
        exp_col2.metric("Stopped Assets", stopped_assets)

        st.subheader("Assets by Region")

        region_counts = (
            asset_df.groupby("Region")
            .size()
            .sort_values(ascending=False)
        )

        st.bar_chart(region_counts)

        st.subheader("Asset Risk Detail")

        selected_asset_id = st.selectbox(
            "Select an asset to review",
            asset_df["Asset ID"].tolist()
        )

        selected_asset = asset_df[
            asset_df["Asset ID"] == selected_asset_id
        ].iloc[0]

        demo_markdown(f"### {selected_asset['Asset ID']}")

        detail_col1, detail_col2, detail_col3 = st.columns(3)

        detail_col1.metric("Asset Type", selected_asset["Asset Type"])
        detail_col2.metric("Region", selected_asset["Region"])
        detail_col3.metric("Risk Score", selected_asset["Risk Score"])

        demo_write("**Account ID:**", selected_asset["Account ID"])
        demo_write("**Private IP:**", selected_asset["Private IP"])
        demo_write("**Public IP:**", selected_asset["Public IP"] or "None")
        demo_write("**State:**", selected_asset["State"])
        demo_write("**Last Scan:**", selected_asset["Last Scan"])

        if selected_asset["Public IP"]:
            st.error(
                "Exposure Finding: This asset has a public IP address. Review security groups, inbound ports, and business justification."
            )
        else:
            demo_success(
                "Exposure Finding: No public IP detected for this asset."
            )

        if selected_asset["Risk Score"] >= 80:
            st.error("Remediation Priority: Critical — immediate review required.")
        elif selected_asset["Risk Score"] >= 50:
            demo_warning("Remediation Priority: High — remediate within SLA.")
        else:
            demo_info("Remediation Priority: Standard monitoring.")

    else:
        demo_info("No assets found yet. Run a Phase 3 client scan first.")



if page == "Remediation Center":

    from remediation_db import (
        get_all_remediation_items_admin,
        update_remediation_status_admin,
    )
    import pandas as pd

    can_update_remediation = has_permission(
        st.session_state.get("user_role"),
        PERMISSION_APPROVE_REMEDIATION,
    )

    st.title("Remediation Center")
    demo_caption("Autonomous remediation recommendations generated from AWS findings")

    remediation_items = (
        get_all_remediation_items_admin()
    )

    columns = [
        "ID",
        "Created At",
        "Category",
        "Priority",
        "Finding",
        "Recommendation",
        "Owner",
        "Status",
        "Risk Score",
        "Occurrence Count",
        "Last Seen At"
    ]

    if remediation_items:
        remediation_df = pd.DataFrame(
            remediation_items,
            columns=columns
        )

        remediation_df["Created At"] = pd.to_datetime(
            remediation_df["Created At"],
            errors="coerce",
            utc=True
        )

        remediation_df["Age (Days)"] = (
            pd.Timestamp.now(tz="UTC") - remediation_df["Created At"]
        ).dt.days.fillna(0).astype(int)

        total_items = len(remediation_df)
        critical_items = len(remediation_df[remediation_df["Priority"] == "CRITICAL"])
        high_items = len(remediation_df[remediation_df["Priority"] == "HIGH"])
        open_items = len(remediation_df[remediation_df["Status"] == "Open"])

        persistent_items = len(
            remediation_df[
                remediation_df["Occurrence Count"] >= 2
            ]
        )

        recurring_critical_items = len(
            remediation_df[
                (remediation_df["Priority"] == "CRITICAL")
                & (remediation_df["Occurrence Count"] >= 2)
            ]
        )

        total_historical_observations = int(
            remediation_df["Occurrence Count"].fillna(1).sum()
        )

        most_repeated_finding = (
            remediation_df.sort_values(
                by="Occurrence Count",
                ascending=False
            ).iloc[0]
            if not remediation_df.empty
            else None
        )
        in_progress_items = len(remediation_df[remediation_df["Status"] == "In Progress"])
        resolved_items = len(remediation_df[remediation_df["Status"] == "Resolved"])
        accepted_risk_items = len(remediation_df[remediation_df["Status"] == "Accepted Risk"])
        oldest_item = remediation_df["Age (Days)"].max() if not remediation_df.empty else 0
        resolution_rate = round((resolved_items / total_items) * 100, 2) if total_items else 0

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric("Total Items", total_items)
        col2.metric("Critical", critical_items)
        col3.metric("High", high_items)
        col4.metric("Open", open_items)

        persistence_col1, persistence_col2, persistence_col3 = st.columns(3)

        persistence_col1.metric(
            "Persistent Findings",
            persistent_items
        )

        persistence_col2.metric(
            "Recurring Critical Findings",
            recurring_critical_items
        )

        persistence_col3.metric(
            "Historical Observations",
            total_historical_observations
        )

        if most_repeated_finding is not None:
            demo_info(
                "Most repeated finding: "
                f"{most_repeated_finding['Finding']} "
                f"({int(most_repeated_finding['Occurrence Count'])} observations)"
            )
        col5.metric("Oldest Item Days", oldest_item)

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

        kpi_col1.metric("In Progress", in_progress_items)
        kpi_col2.metric("Resolved", resolved_items)
        kpi_col3.metric("Accepted Risk", accepted_risk_items)
        kpi_col4.metric("Resolution Rate", f"{resolution_rate}%")

        st.subheader("Persistent Open Findings")

        persistent_findings_df = remediation_df[
            (remediation_df["Status"] == "Open")
            & (remediation_df["Occurrence Count"] >= 2)
        ].copy()

        if not persistent_findings_df.empty:
            persistent_findings_df = persistent_findings_df.sort_values(
                by=[
                    "Occurrence Count",
                    "Risk Score"
                ],
                ascending=[
                    False,
                    False
                ]
            )

            demo_dataframe(
                persistent_findings_df[
                    [
                        "Priority",
                        "Category",
                        "Finding",
                        "Owner",
                        "Risk Score",
                        "Occurrence Count",
                        "Last Seen At"
                    ]
                ],
                width="stretch"
            )

            persistent_findings_csv = (
                persistent_findings_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Persistent Findings CSV",
                data=persistent_findings_csv,
                file_name="dgs_sentinel_persistent_findings.csv",
                mime="text/csv"
            )

        else:
            demo_success("No recurring open findings detected.")

        st.subheader("Remediation Filters")

        filter_col1, filter_col2, filter_col3 = st.columns(3)

        priority_filter = filter_col1.selectbox(
            "Priority",
            ["All"] + sorted(remediation_df["Priority"].dropna().unique().tolist())
        )

        status_filter = filter_col2.selectbox(
            "Status",
            ["All"] + sorted(remediation_df["Status"].dropna().unique().tolist())
        )

        category_filter = filter_col3.selectbox(
            "Category",
            ["All"] + sorted(remediation_df["Category"].dropna().unique().tolist())
        )

        filtered_remediation_df = remediation_df.copy()

        if priority_filter != "All":
            filtered_remediation_df = filtered_remediation_df[
                filtered_remediation_df["Priority"] == priority_filter
            ]

        if status_filter != "All":
            filtered_remediation_df = filtered_remediation_df[
                filtered_remediation_df["Status"] == status_filter
            ]

        if category_filter != "All":
            filtered_remediation_df = filtered_remediation_df[
                filtered_remediation_df["Category"] == category_filter
            ]

        st.subheader("Remediation Summary Charts")

        chart_col1, chart_col2, chart_col3 = st.columns(3)

        with chart_col1:
            demo_write("Items by Priority")
            st.bar_chart(remediation_df["Priority"].value_counts())

        with chart_col2:
            demo_write("Items by Status")
            st.bar_chart(remediation_df["Status"].value_counts())

        with chart_col3:
            demo_write("Items by Category")
            st.bar_chart(remediation_df["Category"].value_counts())

        st.subheader("Remediation Aging")

        if not remediation_df.empty:
            st.bar_chart(
                remediation_df.set_index("Finding")["Age (Days)"]
            )

        st.subheader("Remediation SLA Compliance")

        sla_df = remediation_df.copy()

        sla_df["SLA Bucket"] = pd.cut(
            sla_df["Age (Days)"],
            bins=[-1, 30, 60, 90, 99999],
            labels=["0-30 Days", "31-60 Days", "61-90 Days", "90+ Days"]
        )

        st.bar_chart(
            sla_df["SLA Bucket"].value_counts().sort_index()
        )

        overdue_items = len(
            remediation_df[remediation_df["Age (Days)"] > 90]
        )

        sla_col1, sla_col2 = st.columns(2)

        sla_col1.metric("Overdue Items", overdue_items)

        sla_col2.metric(
            "SLA Compliance %",
            round(((total_items - overdue_items) / total_items) * 100, 2)
            if total_items else 100
        )

        st.subheader("Remediation Queue")

        remediation_df = filtered_remediation_df.sort_values(
            by="Risk Score",
            ascending=False
        )

        demo_dataframe(
            remediation_df,
            width="stretch"
        )

        remediation_csv = remediation_df.to_csv(index=False).encode("utf-8")

        demo_download_button(
            label="Download Filtered Remediation CSV",
            data=remediation_csv,
            file_name="dgs_sentinel_remediation_queue.csv",
            mime="text/csv"
        )

        st.subheader("Top Recommendation")

        top_item = remediation_df.iloc[0]

        demo_markdown(f"### {top_item['Finding']}")
        demo_write("**Priority:**", top_item["Priority"])
        demo_write("**Category:**", top_item["Category"])
        demo_write("**Owner:**", top_item["Owner"])
        demo_write("**Recommendation:**", top_item["Recommendation"])

        st.subheader("Update Remediation Status")

        selected_item_id = st.selectbox(
            "Select remediation item ID",
            remediation_df["ID"].tolist()
        )

        new_status = st.selectbox(
            "New status",
            [
                "Open",
                "In Progress",
                "Resolved",
                "Accepted Risk"
            ],
            disabled=not can_update_remediation,
        )

        if not can_update_remediation:
            demo_info(
                "Your role has read-only access to remediation status."
            )

        if st.button(
            "Update Remediation Status",
            disabled=not can_update_remediation,
        ):
            if not can_update_remediation:
                st.error(
                    "Your role is not authorized to update remediation status."
                )
            else:
                update_remediation_status_admin(
                    int(selected_item_id),
                    new_status
                )

                demo_success(
                    f"Remediation item {selected_item_id} updated to {new_status}."
                )

                st.rerun()

    else:
        demo_info("No remediation items found yet. Run a scan to generate recommendations.")




if page == "Execution Center":

    from remediation_execution import (
        get_execution_actions,
        update_execution_action,
        simulate_execution,
        simulate_all_approved_actions,
        execute_live_action,
        verify_execution_evidence,
        create_actions_from_remediation_plan,
    )
    from remediation_audit import get_remediation_audit
    from splunk_audit_export import export_audit_events
    from remediation_guardrails import GUARDRAILS
    from remediation_live_actions import (
        get_adapter_for_action,
        build_execution_plan,
        get_adapter_readiness_matrix
    )
    import pandas as pd

    st.title("Execution Center")
    demo_caption("Autonomous remediation execution queue")

    current_user_role = st.session_state.get("user_role")
    can_approve_remediation = has_permission(
        current_user_role,
        PERMISSION_APPROVE_REMEDIATION,
    )
    can_execute_remediation = has_permission(
        current_user_role,
        PERMISSION_EXECUTE_REMEDIATION,
    )

    st.subheader("Remediation Guardrail Status")

    guardrail_col1, guardrail_col2, guardrail_col3 = st.columns(3)

    guardrail_col1.metric(
        "Live AWS Execution",
        "Enabled" if GUARDRAILS.live_execution_enabled else "Disabled"
    )

    guardrail_col2.metric(
        "Human Approval Required",
        "Yes" if GUARDRAILS.require_human_approval else "No"
    )

    guardrail_col3.metric(
        "Confirmation Phrase Required",
        "Yes" if GUARDRAILS.require_confirmation_phrase else "No"
    )

    if GUARDRAILS.live_execution_enabled:
        demo_warning(
            "Live AWS remediation is enabled. Approved actions may modify AWS resources."
        )
    else:
        demo_success(
            "Safe mode is active. Live AWS remediation is disabled. "
            "Execution Center actions remain in simulation mode."
        )

    st.subheader("Live Adapter Readiness Matrix")

    adapter_matrix_df = pd.DataFrame(
        get_adapter_readiness_matrix()
    )

    demo_dataframe(
        adapter_matrix_df,
        width="stretch"
    )

    demo_caption(
        "All adapters remain locked to simulation or workflow-only mode. "
        "No live AWS remediation adapters are enabled."
    )

    actions = get_execution_actions()

    columns = [
        "ID",
        "Created At",
        "Finding",
        "Action Type",
        "Priority",
        "Approval Status",
        "Execution Status",
        "Execution Mode",
        "Notes",
        "AWS Account ID",
        "Client Name",
        "Role ARN",
        "Adapter",
        "Resource ID",
        "Request ID",
        "Verification Request ID",
        "Verification Status",
        "Result Message",
        "Executed At",
        "Evidence Hash",
        "Evidence Authentication Type",
        "Evidence Key ID",
        "Cloud Provider",
        "Azure Subscription ID",
        "Azure Tenant ID",
        "Azure Client ID",
    ]

    if actions:
        actions_df = pd.DataFrame(
            actions,
            columns=columns
        )

        pending_approval = len(
            actions_df[
                actions_df["Approval Status"] == "Pending Approval"
            ]
        )

        approved_actions = len(
            actions_df[
                actions_df["Approval Status"] == "Approved"
            ]
        )

        completed_actions = len(
            actions_df[
                actions_df["Execution Status"] == "Completed"
            ]
        )

        failed_actions = len(
            actions_df[
                actions_df["Execution Status"] == "Failed"
            ]
        )

        total_actions = len(actions_df)

        completion_rate = round(
            (completed_actions / total_actions) * 100,
            2
        ) if total_actions else 0

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric("Pending Approval", pending_approval)
        col2.metric("Approved", approved_actions)
        col3.metric("Completed", completed_actions)
        col4.metric("Failed", failed_actions)
        col5.metric("Completion Rate", f"{completion_rate}%")

        st.subheader("Execution Analytics")

        analytics_df = actions_df.copy()

        analytics_df["Adapter"] = analytics_df[
            "Action Type"
        ].apply(get_adapter_for_action)

        analytics_col1, analytics_col2 = st.columns(2)

        with analytics_col1:
            demo_write("Actions by Execution Status")
            st.bar_chart(
                analytics_df["Execution Status"].value_counts()
            )

        with analytics_col2:
            demo_write("Actions by Adapter")
            st.bar_chart(
                analytics_df["Adapter"].value_counts()
            )

        st.subheader("Execution Queue Filters")

        queue_filter_col1, queue_filter_col2, queue_filter_col3 = st.columns(3)

        approval_filter = queue_filter_col1.selectbox(
            "Filter by approval",
            ["All"] + sorted(
                actions_df["Approval Status"]
                .dropna()
                .unique()
                .tolist()
            ),
            key="execution_approval_filter"
        )

        execution_filter = queue_filter_col2.selectbox(
            "Filter by execution status",
            ["All"] + sorted(
                actions_df["Execution Status"]
                .dropna()
                .unique()
                .tolist()
            ),
            key="execution_status_filter"
        )

        adapter_filter = queue_filter_col3.selectbox(
            "Filter by adapter",
            ["All"] + sorted(
                analytics_df["Adapter"]
                .dropna()
                .unique()
                .tolist()
            ),
            key="execution_adapter_filter"
        )

        filtered_actions_df = analytics_df.copy()

        if approval_filter != "All":
            filtered_actions_df = filtered_actions_df[
                filtered_actions_df["Approval Status"] == approval_filter
            ]

        if execution_filter != "All":
            filtered_actions_df = filtered_actions_df[
                filtered_actions_df["Execution Status"] == execution_filter
            ]

        if adapter_filter != "All":
            filtered_actions_df = filtered_actions_df[
                filtered_actions_df["Adapter"] == adapter_filter
            ]

        st.subheader("Execution Queue")

        queue_display_df = filtered_actions_df.drop(
            columns=["Role ARN"],
            errors="ignore",
        )

        demo_dataframe(
            queue_display_df,
            width="stretch"
        )

        execution_export_df = queue_display_df.copy()

        execution_export_df["Resource Type"] = execution_export_df.apply(
            lambda row: build_execution_plan(
                action_type=row["Action Type"],
                finding=row["Finding"]
            ).get("resource_type", "UNKNOWN"),
            axis=1
        )

        execution_export_df["Resource ID"] = execution_export_df.apply(
            lambda row: build_execution_plan(
                action_type=row["Action Type"],
                finding=row["Finding"]
            ).get("resource_id", "UNKNOWN"),
            axis=1
        )

        execution_queue_csv = (
            execution_export_df
            .to_csv(index=False)
            .encode("utf-8")
        )

        demo_download_button(
            label="Download Filtered Execution Summary CSV",
            data=execution_queue_csv,
            file_name="dgs_sentinel_execution_summary.csv",
            mime="text/csv"
        )

        st.subheader("Execution Action Detail")

        selected_action_id = st.selectbox(
            "Select action ID",
            actions_df["ID"].tolist()
        )

        selected_action = actions_df[
            actions_df["ID"] == selected_action_id
        ].iloc[0]

        selected_adapter = get_adapter_for_action(
            selected_action["Action Type"]
        )

        detail_col1, detail_col2, detail_col3 = st.columns(3)

        detail_col1.metric(
            "Priority",
            selected_action["Priority"]
        )

        detail_col2.metric(
            "Approval Status",
            selected_action["Approval Status"]
        )

        detail_col3.metric(
            "Execution Status",
            selected_action["Execution Status"]
        )

        demo_write("**Finding:**", selected_action["Finding"])
        demo_write("**Action Type:**", selected_action["Action Type"])
        demo_write("**Controlled Adapter:**", selected_adapter)
        demo_write("**Execution Mode:**", selected_action["Execution Mode"])
        demo_write("**Client Name:**", selected_action["Client Name"] or "Unbound")
        demo_write(
            "**AWS Account ID:**",
            selected_action["AWS Account ID"] or "Unbound",
        )
        demo_write("**Notes:**", selected_action["Notes"])

        st.subheader("Execution Evidence")

        evidence_col1, evidence_col2, evidence_col3 = st.columns(3)

        evidence_col1.metric(
            "Adapter",
            selected_action["Adapter"] or "Not Recorded",
        )

        evidence_col2.metric(
            "Verification Status",
            selected_action["Verification Status"] or "Not Recorded",
        )

        evidence_col3.metric(
            "Executed At",
            selected_action["Executed At"] or "Not Recorded",
        )

        demo_write(
            "**Resource ID:**",
            selected_action["Resource ID"] or "Not Recorded",
        )
        demo_write(
            "**AWS Request ID:**",
            selected_action["Request ID"] or "Not Recorded",
        )
        demo_write(
            "**Verification Request ID:**",
            selected_action["Verification Request ID"] or "Not Recorded",
        )
        demo_write(
            "**Execution Result:**",
            selected_action["Result Message"] or "Not Recorded",
        )
        demo_write(
            "**Evidence Hash:**",
            selected_action["Evidence Hash"] or "Not Recorded",
        )
        demo_write(
            "**Evidence Authentication:**",
            selected_action["Evidence Authentication Type"]
            or "Not Recorded",
        )
        demo_write(
            "**Evidence Key ID:**",
            selected_action["Evidence Key ID"] or "Not Recorded",
        )

        try:
            evidence_integrity = verify_execution_evidence(
                int(selected_action_id)
            )

            integrity_status = evidence_integrity.get(
                "status",
                "UNKNOWN",
            )

            if integrity_status == "VERIFIED":
                demo_success(
                    "Execution evidence integrity verified."
                )
            elif integrity_status == "TAMPERED":
                st.error(
                    "Execution evidence authentication failed. "
                    "Stored evidence may have been modified."
                )
            elif integrity_status == "KEY_MISMATCH":
                st.error(
                    "Execution evidence was authenticated with a "
                    "different HMAC key."
                )
            elif integrity_status == "UNSUPPORTED":
                demo_warning(
                    "This evidence record uses an unsupported "
                    "authentication method."
                )
            else:
                demo_warning(
                    "No authenticated evidence signature is available "
                    "for this action."
                )

        except ValueError as error:
            st.error(
                f"Unable to verify execution evidence: {error}"
            )

        st.subheader("Dry-Run Execution Plan")

        try:
            execution_plan = build_execution_plan(
                action_type=selected_action["Action Type"],
                finding=selected_action["Finding"]
            )

            plan_col1, plan_col2, plan_col3 = st.columns(3)

            plan_col1.metric(
                "Resource Type",
                execution_plan.get("resource_type", "UNKNOWN")
            )

            plan_col2.metric(
                "Resource ID",
                execution_plan.get("resource_id", "UNKNOWN")
            )

            plan_col3.metric(
                "Target Supported",
                "Yes" if execution_plan.get("target_supported") else "No"
            )

            demo_json(execution_plan)

            if execution_plan.get("live_execution_enabled"):
                demo_warning(
                    "Live execution is enabled for this action. Review carefully."
                )
            else:
                demo_success(
                    "Dry-run only. No AWS resources will be modified."
                )

        except Exception as e:
            st.error(f"Unable to build dry-run execution plan: {e}")

        st.subheader("Execution Approval Workflow")

        approval_options = [
            "Pending Approval",
            "Approved",
            "Rejected"
        ]

        execution_options = [
            "Not Started",
            "Ready",
            "Executing",
            "Completed",
            "Failed"
        ]

        current_approval = selected_action["Approval Status"]
        current_execution = selected_action["Execution Status"]

        approval_index = (
            approval_options.index(current_approval)
            if current_approval in approval_options
            else 0
        )

        execution_index = (
            execution_options.index(current_execution)
            if current_execution in execution_options
            else 0
        )

        approval_status = st.selectbox(
            "Approval status",
            approval_options,
            index=approval_index,
            disabled=not can_approve_remediation,
        )

        execution_status = st.selectbox(
            "Execution status",
            execution_options,
            index=execution_index,
            disabled=not can_execute_remediation,
        )

        can_update_execution_action = (
            can_approve_remediation
            or can_execute_remediation
        )

        if not can_update_execution_action:
            demo_info(
                "Your role has read-only access to remediation actions."
            )

        if st.button(
            "Update Execution Action",
            disabled=not can_update_execution_action,
        ):
            if not can_update_execution_action:
                st.error(
                    "Your role is not authorized to update remediation actions."
                )
            else:
                try:
                    update_execution_action(
                        int(selected_action_id),
                        approval_status=(
                            approval_status
                            if can_approve_remediation
                            else current_approval
                        ),
                        execution_status=(
                            execution_status
                            if can_execute_remediation
                            else current_execution
                        ),
                    )

                    demo_success(
                        f"Execution action {selected_action_id} updated."
                    )

                    st.rerun()

                except ValueError as e:
                    st.error(f"Workflow update blocked: {e}")

                except Exception as e:
                    st.error(f"Unable to update execution action: {e}")

        st.subheader("Run Approved Simulation")

        demo_caption(
            "Simulation mode does not modify AWS resources. "
            "It validates the remediation workflow and creates an audit record."
        )

        if st.button(
            "Run Approved Simulation",
            disabled=not can_execute_remediation,
        ):
            if not can_execute_remediation:
                st.error(
                    "Your role is not authorized to execute remediation."
                )
            else:
                try:
                    simulation_result = simulate_execution(
                        int(selected_action_id)
                    )

                    demo_success(
                        f"Simulation completed for action "
                        f"{simulation_result.get('action_id')}."
                    )

                    demo_json(simulation_result)

                    st.rerun()

                except Exception as e:
                    st.error(f"Simulation failed: {e}")

        st.subheader("Guarded Live Cloud Remediation")

        live_enabled_adapters = {
            "S3_BLOCK_PUBLIC_ACCESS",
            "AZURE_STORAGE_HARDENING",
            "AZURE_NSG_RULE_RESTRICTION",
        }

        is_azure_storage_live_action = (
            selected_adapter == "AZURE_STORAGE_HARDENING"
        )
        is_azure_nsg_live_action = (
            selected_adapter == "AZURE_NSG_RULE_RESTRICTION"
        )
        is_azure_live_action = (
            is_azure_storage_live_action
            or is_azure_nsg_live_action
        )
        is_aws_live_action = (
            selected_adapter == "S3_BLOCK_PUBLIC_ACCESS"
        )

        demo_caption(
            "Live remediation is restricted to approved actions, "
            "resources permanently bound to the action, and the exact "
            "authorization phrase."
        )

        if not can_execute_remediation:
            demo_info(
                "Your role is not authorized to execute live remediation."
            )

        elif not GUARDRAILS.live_execution_enabled:
            demo_info(
                "Live remediation is disabled. Set "
                "DGS_LIVE_REMEDIATION_ENABLED=true only in an "
                "authorized environment."
            )

        elif selected_adapter not in live_enabled_adapters:
            demo_info(
                "This adapter remains simulation-only. Guarded live "
                "execution is available only for approved S3 and Azure "
                "Storage remediation actions."
            )

        elif selected_action["Approval Status"] != "Approved":
            demo_warning(
                "This action must be approved before live execution."
            )

        elif selected_action["Execution Status"] == "Completed":
            demo_info(
                "This remediation action has already been completed."
            )

        elif is_azure_live_action:
            live_client_name = selected_action["Client Name"]
            live_subscription_id = selected_action[
                "Azure Subscription ID"
            ]
            live_tenant_id = selected_action["Azure Tenant ID"]
            live_azure_client_id = selected_action["Azure Client ID"]

            missing_azure_binding = any(
                pd.isna(value) or not str(value).strip()
                for value in (
                    live_subscription_id,
                    live_tenant_id,
                    live_azure_client_id,
                )
            )

            if missing_azure_binding:
                demo_warning(
                    "This action is missing its bound Azure "
                    "subscription, tenant, or client ID and cannot "
                    "be executed live."
                )

            elif create_azure_credential is None:
                demo_warning(
                    "The Azure credential module is unavailable."
                )

            elif (
                is_azure_storage_live_action
                and StorageManagementClient is None
            ):
                demo_warning(
                    "The Azure Storage Management SDK is unavailable."
                )

            elif (
                is_azure_nsg_live_action
                and NetworkManagementClient is None
            ):
                demo_warning(
                    "The Azure Network Management SDK is unavailable."
                )

            else:
                live_subscription_id = str(
                    live_subscription_id
                ).strip()
                live_tenant_id = str(live_tenant_id).strip()
                live_azure_client_id = str(
                    live_azure_client_id
                ).strip()

                live_plan = build_execution_plan(
                    action_type=selected_action["Action Type"],
                    finding=selected_action["Finding"],
                )

                demo_write(
                    "**Bound client:**",
                    live_client_name or "Unnamed Client",
                )
                demo_write(
                    "**Cloud provider:**",
                    "Azure",
                )
                demo_write(
                    "**Bound Azure subscription:**",
                    live_subscription_id,
                )
                demo_write(
                    "**Target Azure resource:**",
                    live_plan.get("resource_id", "UNKNOWN"),
                )

                if is_azure_nsg_live_action:
                    demo_write(
                        "**Target NSG rule:**",
                        live_plan.get("rule_name", "UNKNOWN"),
                    )

                azure_remediation_label = (
                    "Azure Storage"
                    if is_azure_storage_live_action
                    else "Azure NSG Rule"
                )

                live_azure_secret = st.text_input(
                    "Azure client secret for live remediation",
                    type="password",
                    key="live_azure_remediation_secret",
                    help=(
                        "Used only for this live execution. "
                        "The secret is not stored."
                    ),
                )

                confirmation_phrase = st.text_input(
                    "Live execution confirmation phrase",
                    type="password",
                    key="live_remediation_confirmation",
                    help=(
                        "Enter exactly: "
                        "AUTHORIZE LIVE AWS REMEDIATION"
                    ),
                )

                operator_acknowledgement = st.checkbox(
                    (
                        "I confirm that this approved action may "
                        "permanently modify the Azure subscription "
                        "bound to this action."
                    ),
                    key="live_remediation_acknowledgement",
                )

                live_button_enabled = (
                    operator_acknowledgement
                    and bool(live_azure_secret)
                    and confirmation_phrase
                    == "AUTHORIZE LIVE AWS REMEDIATION"
                )

                if st.button(
                    (
                        f"Execute Guarded Live "
                        f"{azure_remediation_label} Remediation"
                    ),
                    disabled=not live_button_enabled,
                    key="execute_guarded_live_remediation",
                ):
                    try:
                        credential = create_azure_credential(
                            tenant_id=live_tenant_id,
                            client_id=live_azure_client_id,
                            client_secret=live_azure_secret,
                        )

                        live_azure_storage_client = None
                        live_azure_network_client = None

                        if is_azure_storage_live_action:
                            live_azure_storage_client = (
                                StorageManagementClient(
                                    credential,
                                    live_subscription_id,
                                )
                            )

                        elif is_azure_nsg_live_action:
                            live_azure_network_client = (
                                NetworkManagementClient(
                                    credential,
                                    live_subscription_id,
                                )
                            )

                        live_result = execute_live_action(
                            action_id=int(selected_action_id),
                            expected_subscription_id=(
                                live_subscription_id
                            ),
                            azure_storage_client=(
                                live_azure_storage_client
                            ),
                            azure_network_client=(
                                live_azure_network_client
                            ),
                            confirmation_phrase=confirmation_phrase,
                            actor=(
                                settings.app_username
                                or "Authenticated Operator"
                            ),
                        )

                        demo_success(
                            f"Guarded live {azure_remediation_label} "
                            "remediation completed and verified."
                        )
                        demo_json(live_result)
                        st.rerun()

                    except ValueError as error:
                        st.error(
                            f"Live remediation blocked: {error}"
                        )

                    except Exception as error:
                        logger.exception(
                            "Guarded Azure live remediation failed."
                        )
                        st.error(
                            f"Live remediation failed: {error}"
                        )

        elif is_aws_live_action:
            live_client_name = selected_action["Client Name"]
            live_account_id = selected_action["AWS Account ID"]
            live_role_arn = selected_action["Role ARN"]

            if (
                pd.isna(live_account_id)
                or not str(live_account_id).strip()
            ):
                demo_warning(
                    "This action is not bound to an AWS account and "
                    "cannot be executed live."
                )

            elif (
                pd.isna(live_role_arn)
                or not str(live_role_arn).strip()
            ):
                demo_warning(
                    "This action has no bound remediation role. "
                    "Internal or legacy actions remain simulation-only."
                )

            else:
                live_account_id = str(live_account_id).strip()
                live_role_arn = str(live_role_arn).strip()

                live_plan = build_execution_plan(
                    action_type=selected_action["Action Type"],
                    finding=selected_action["Finding"],
                )

                demo_write(
                    "**Bound client:**",
                    live_client_name or "Unnamed Client",
                )
                demo_write(
                    "**Cloud provider:**",
                    "AWS",
                )
                demo_write(
                    "**Bound AWS account:**",
                    live_account_id,
                )
                demo_write(
                    "**Target S3 bucket:**",
                    live_plan.get("resource_id", "UNKNOWN"),
                )

                confirmation_phrase = st.text_input(
                    "Live execution confirmation phrase",
                    type="password",
                    key="live_remediation_confirmation",
                    help=(
                        "Enter exactly: "
                        "AUTHORIZE LIVE AWS REMEDIATION"
                    ),
                )

                operator_acknowledgement = st.checkbox(
                    (
                        "I confirm that this approved action may "
                        "permanently modify the AWS account bound "
                        "to this action."
                    ),
                    key="live_remediation_acknowledgement",
                )

                live_button_enabled = (
                    operator_acknowledgement
                    and confirmation_phrase
                    == "AUTHORIZE LIVE AWS REMEDIATION"
                )

                if st.button(
                    "Execute Guarded Live S3 Remediation",
                    disabled=not live_button_enabled,
                    key="execute_guarded_live_remediation",
                ):
                    try:
                        client_session = assume_client_role(
                            live_role_arn
                        )

                        if client_session is None:
                            raise ValueError(
                                "Unable to assume the remediation "
                                "role bound to this action."
                            )

                        live_s3_client = client_session.client("s3")

                        live_result = execute_live_action(
                            action_id=int(selected_action_id),
                            expected_account_id=live_account_id,
                            s3_client=live_s3_client,
                            confirmation_phrase=confirmation_phrase,
                            actor=(
                                settings.app_username
                                or "Authenticated Operator"
                            ),
                        )

                        demo_success(
                            "Guarded live S3 remediation completed "
                            "and verified."
                        )
                        demo_json(live_result)
                        st.rerun()

                    except ValueError as error:
                        st.error(
                            f"Live remediation blocked: {error}"
                        )

                    except Exception as error:
                        logger.exception(
                            "Guarded AWS live remediation failed."
                        )
                        st.error(
                            f"Live remediation failed: {error}"
                        )

        st.subheader("Bulk Approved Simulation")

        demo_caption(
            "Runs all approved actions that are not already completed or failed. "
            "Simulation mode does not modify AWS resources."
        )

        if st.button(
            "Run All Approved Simulations",
            disabled=not can_execute_remediation,
        ):
            if not can_execute_remediation:
                st.error(
                    "Your role is not authorized to execute remediation."
                )
            else:
                bulk_results = simulate_all_approved_actions()

                if bulk_results:
                    demo_success(
                        f"Processed {len(bulk_results)} approved remediation actions."
                    )

                    demo_dataframe(
                        pd.DataFrame(bulk_results),
                        width="stretch"
                    )

                    st.rerun()

                else:
                    demo_info("No approved pending actions are available.")

        st.subheader("Execution Audit Trail")

        audit_rows = get_remediation_audit()

        audit_columns = [
            "Audit ID",
            "Created At",
            "Action ID",
            "Event Type",
            "Event Detail",
            "Actor"
        ]

        if audit_rows:
            audit_df = pd.DataFrame(
                audit_rows,
                columns=audit_columns
            )

            selected_audit_action = st.selectbox(
                "Filter audit trail by action ID",
                ["All"] + sorted(
                    audit_df["Action ID"]
                    .dropna()
                    .astype(int)
                    .unique()
                    .tolist()
                ),
                key="audit_action_filter"
            )

            if selected_audit_action != "All":
                audit_df = audit_df[
                    audit_df["Action ID"] == int(selected_audit_action)
                ]

            demo_dataframe(
                audit_df,
                width="stretch"
            )

            audit_csv = audit_df.to_csv(index=False).encode("utf-8")

            demo_download_button(
                label="Download Audit Trail CSV",
                data=audit_csv,
                file_name="dgs_sentinel_execution_audit.csv",
                mime="text/csv"
            )

            st.subheader("Splunk SIEM Export")

            splunk_configured = bool(
                settings.splunk_hec_url
                and settings.splunk_hec_token
            )

            if splunk_configured:
                demo_info(
                    "Splunk HEC is configured. "
                    f"Index: {settings.splunk_index}; "
                    f"Source: {settings.splunk_source}; "
                    f"Sourcetype: {settings.splunk_sourcetype}"
                )
            else:
                demo_info(
                    "Configure SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN "
                    "to enable secure audit-event export."
                )

            if st.button(
                "Send Filtered Audit Events to Splunk",
                disabled=(
                    not splunk_configured
                    or not can_execute_remediation
                ),
                key="send_audit_events_to_splunk",
            ):
                export_result = export_audit_events(
                    audit_df.itertuples(
                        index=False,
                        name=None,
                    )
                )

                if export_result["failed"] == 0:
                    demo_success(
                        "Splunk export completed: "
                        f"{export_result['sent']} event(s) sent."
                    )
                else:
                    st.warning(
                        "Splunk export completed with failures: "
                        f"{export_result['sent']} sent, "
                        f"{export_result['failed']} failed."
                    )

                demo_dataframe(
                    pd.DataFrame(export_result["results"]),
                    width="stretch",
                )

        else:
            demo_info("No execution audit events found yet.")

    else:
        demo_info("No remediation actions have been generated yet.")



if page == "Axonius CAASM Dashboard":

    from axonius_connector import (
        axonius_configured,
        get_axonius_assets,
        get_axonius_identities,
        get_axonius_coverage_sources
    )
    from axonius_risk_engine import (
        calculate_caasm_metrics,
        generate_caasm_policy_findings,
        calculate_identity_governance_metrics,
        generate_identity_governance_rows,
        calculate_coverage_gap_metrics,
        generate_coverage_gap_findings,
        generate_correlated_exposure_rows,
        calculate_correlation_metrics,
        generate_caasm_executive_recommendations
    )
    from caasm_alert_service import process_correlation_alerts
    from caasm_alert_db import (
        acknowledge_alert,
        get_alerts,
        resolve_alert,
    )
    import pandas as pd

    st.title("Axonius CAASM Dashboard")
    demo_caption(
        "Cyber asset attack surface management and identity-risk analytics"
    )

    try:
        asset_response = get_axonius_assets()
        identity_response = get_axonius_identities()
        coverage_response = get_axonius_coverage_sources()

        connector_mode = asset_response.get("mode", "Unknown")
        assets = asset_response.get("assets", [])
        identities = identity_response.get("identities", [])
        coverage_sources = coverage_response.get("coverage_sources", [])

        if connector_mode == "Live" and axonius_configured():
            demo_success("Axonius connector mode: Live API")
        else:
            demo_info(
                "Axonius connector mode: Mock data. "
                "Add API credentials later to enable the live connector."
            )

        metrics = calculate_caasm_metrics(
            assets=assets,
            identities=identities
        )

        policy_findings = generate_caasm_policy_findings(
            assets=assets,
            identities=identities
        )

        identity_governance_metrics = calculate_identity_governance_metrics(
            identities=identities
        )

        identity_governance_rows = generate_identity_governance_rows(
            identities=identities
        )

        coverage_gap_metrics = calculate_coverage_gap_metrics(
            coverage_sources=coverage_sources
        )

        coverage_gap_findings = generate_coverage_gap_findings(
            coverage_sources=coverage_sources
        )

        correlation_rows = generate_correlated_exposure_rows(
            assets=assets,
            identities=identities,
            coverage_sources=coverage_sources
        )

        correlation_metrics = calculate_correlation_metrics(
            correlation_rows=correlation_rows
        )

        executive_recommendations = generate_caasm_executive_recommendations(
            metrics=metrics,
            identity_governance_metrics=identity_governance_metrics,
            coverage_gap_metrics=coverage_gap_metrics,
            policy_findings=policy_findings,
            coverage_gap_findings=coverage_gap_findings,
            correlation_metrics=correlation_metrics,
            correlation_rows=correlation_rows
        )

        st.subheader("Executive CAASM Scorecard")

        score_col1, score_col2, score_col3 = st.columns(3)

        score_col1.metric(
            "CAASM Score",
            metrics.get("CAASM Score", 0)
        )

        score_col2.metric(
            "Asset Coverage %",
            metrics.get("Asset Coverage %", 0)
        )

        score_col3.metric(
            "MFA Coverage %",
            metrics.get("MFA Coverage %", 0)
        )

        risk_col1, risk_col2, risk_col3 = st.columns(3)

        risk_col1.metric(
            "Unmanaged Assets",
            metrics.get("Unmanaged Assets", 0)
        )

        risk_col2.metric(
            "Orphaned Accounts",
            metrics.get("Orphaned Accounts", 0)
        )

        risk_col3.metric(
            "Privileged Users",
            metrics.get("Privileged Users", 0)
        )

        st.subheader("Asset Inventory")

        if assets:
            axonius_asset_df = pd.DataFrame(assets)

            axonius_asset_df = axonius_asset_df.sort_values(
                by="risk_score",
                ascending=False
            )

            demo_dataframe(
                axonius_asset_df,
                width="stretch"
            )

            st.subheader("Asset Coverage Analytics")

            coverage_df = pd.DataFrame(
                {
                    "Coverage Status": [
                        "Managed Assets",
                        "Unmanaged Assets"
                    ],
                    "Count": [
                        metrics.get("Managed Assets", 0),
                        metrics.get("Unmanaged Assets", 0)
                    ]
                }
            )

            st.bar_chart(
                coverage_df.set_index("Coverage Status")["Count"]
            )

        else:
            demo_info("No Axonius asset records are available.")

        st.subheader("Correlated Exposure Analytics")

        correlation_col1, correlation_col2, correlation_col3 = st.columns(3)

        correlation_col1.metric(
            "Critical Correlations",
            correlation_metrics.get("Critical Correlations", 0)
        )

        correlation_col2.metric(
            "High Correlations",
            correlation_metrics.get("High Correlations", 0)
        )

        correlation_col3.metric(
            "Average Correlated Risk",
            correlation_metrics.get(
                "Average Correlated Risk Score",
                0
            )
        )

        correlation_col4, correlation_col5, correlation_col6 = st.columns(3)

        correlation_col4.metric(
            "Unmatched Asset Owners",
            correlation_metrics.get("Unmatched Asset Owners", 0)
        )

        correlation_col5.metric(
            "Unmanaged Correlated Assets",
            correlation_metrics.get(
                "Unmanaged Correlated Assets",
                0
            )
        )

        correlation_col6.metric(
            "Disconnected Sources",
            correlation_metrics.get(
                "Assets With Disconnected Sources",
                0
            )
        )

        if correlation_rows:
            correlation_df = pd.DataFrame(
                correlation_rows
            )

            demo_dataframe(
                correlation_df,
                width="stretch"
            )

            st.subheader("Correlated Risk by Asset")

            st.bar_chart(
                correlation_df.set_index("Hostname")[
                    "Correlated Risk Score"
                ]
            )

            correlation_csv = (
                correlation_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Correlated Exposure CSV",
                data=correlation_csv,
                file_name=(
                    "dgs_sentinel_caasm_correlated_exposure.csv"
                ),
                mime="text/csv"
            )

        else:
            demo_info(
                "No asset-identity correlation records are available."
            )

        st.subheader("Correlated Exposure Alerting")

        current_caasm_role = st.session_state.get(
            "user_role"
        )

        can_process_caasm_alerts = has_permission(
            current_caasm_role,
            PERMISSION_RUN_SCANS,
        )

        can_manage_caasm_alerts = has_permission(
            current_caasm_role,
            PERMISSION_EXECUTE_REMEDIATION,
        )

        splunk_alerting_configured = bool(
            settings.splunk_hec_url
            and settings.splunk_hec_token
        )

        alert_control_col1, alert_control_col2 = st.columns(2)

        with alert_control_col1:
            alert_cooldown_minutes = st.number_input(
                "Alert notification cooldown (minutes)",
                min_value=0,
                max_value=10080,
                value=60,
                step=15,
                key="caasm_alert_cooldown_minutes",
            )

        with alert_control_col2:
            export_caasm_alerts_to_splunk = st.checkbox(
                "Send due alerts to Splunk HEC",
                value=False,
                disabled=not splunk_alerting_configured,
                key="export_caasm_alerts_to_splunk",
            )

        if splunk_alerting_configured:
            demo_info(
                "Splunk HEC alert delivery is available. "
                f"Index: {settings.splunk_index}; "
                f"Source: {settings.splunk_source}; "
                f"Sourcetype: {settings.splunk_sourcetype}"
            )
        else:
            demo_info(
                "Configure SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN "
                "to enable correlated-exposure alert delivery."
            )

        if st.button(
            "Process Correlated Exposure Alerts",
            disabled=not can_process_caasm_alerts,
            key="process_caasm_correlation_alerts",
        ):
            alert_result = process_correlation_alerts(
                correlation_rows,
                cooldown_minutes=int(
                    alert_cooldown_minutes
                ),
                export_to_splunk=(
                    export_caasm_alerts_to_splunk
                ),
            )

            demo_success(
                "Alert processing completed: "
                f"{alert_result['created']} created, "
                f"{alert_result['updated']} updated, "
                f"{alert_result['reopened']} reopened."
            )

            if export_caasm_alerts_to_splunk:
                delivery = alert_result["delivery"]

                if delivery["failed"]:
                    demo_warning(
                        "Splunk delivery completed with "
                        f"{delivery['sent']} sent and "
                        f"{delivery['failed']} failed."
                    )
                else:
                    demo_success(
                        "Splunk delivery completed: "
                        f"{delivery['sent']} alerts sent."
                    )

        stored_caasm_alerts = get_alerts()

        alert_metric_col1, alert_metric_col2, alert_metric_col3 = st.columns(3)

        open_caasm_alerts = [
            alert
            for alert in stored_caasm_alerts
            if alert.get("status") == "OPEN"
        ]

        acknowledged_caasm_alerts = [
            alert
            for alert in stored_caasm_alerts
            if alert.get("status") == "ACKNOWLEDGED"
        ]

        resolved_caasm_alerts = [
            alert
            for alert in stored_caasm_alerts
            if alert.get("status") == "RESOLVED"
        ]

        alert_metric_col1.metric(
            "Open Alerts",
            len(open_caasm_alerts),
        )

        alert_metric_col2.metric(
            "Acknowledged Alerts",
            len(acknowledged_caasm_alerts),
        )

        alert_metric_col3.metric(
            "Resolved Alerts",
            len(resolved_caasm_alerts),
        )

        if stored_caasm_alerts:
            caasm_alert_df = pd.DataFrame(
                stored_caasm_alerts
            )

            alert_display_columns = [
                "id",
                "priority",
                "status",
                "hostname",
                "source",
                "owner",
                "risk_score",
                "occurrence_count",
                "notification_count",
                "last_seen_at",
                "last_notified_at",
                "risk_drivers",
            ]

            demo_dataframe(
                caasm_alert_df[
                    [
                        column
                        for column in alert_display_columns
                        if column in caasm_alert_df.columns
                    ]
                ],
                width="stretch",
            )

            manageable_caasm_alerts = [
                alert
                for alert in stored_caasm_alerts
                if alert.get("status") in {
                    "OPEN",
                    "ACKNOWLEDGED",
                }
            ]

            if manageable_caasm_alerts:
                alert_label_map = {
                    (
                        f"{alert['id']} | "
                        f"{alert['priority']} | "
                        f"{alert.get('hostname') or 'Unknown'} | "
                        f"{alert['status']}"
                    ): alert
                    for alert in manageable_caasm_alerts
                }

                selected_alert_label = st.selectbox(
                    "Select alert for lifecycle action",
                    list(alert_label_map),
                    key="selected_caasm_alert_action",
                )

                selected_caasm_alert = alert_label_map[
                    selected_alert_label
                ]

                resolution_note = st.text_input(
                    "Resolution note",
                    key="caasm_alert_resolution_note",
                )

                alert_action_col1, alert_action_col2 = st.columns(2)

                alert_actor = (
                    settings.app_username
                    or current_caasm_role
                    or "Authenticated User"
                )

                if alert_action_col1.button(
                    "Acknowledge Selected Alert",
                    disabled=(
                        not can_manage_caasm_alerts
                        or selected_caasm_alert["status"]
                        != "OPEN"
                    ),
                    key="acknowledge_selected_caasm_alert",
                ):
                    changed = acknowledge_alert(
                        int(selected_caasm_alert["id"]),
                        actor=str(alert_actor),
                    )

                    if changed:
                        demo_success(
                            "The selected alert was acknowledged."
                        )
                        st.rerun()
                    else:
                        demo_warning(
                            "The selected alert could not be acknowledged."
                        )

                if alert_action_col2.button(
                    "Resolve Selected Alert",
                    disabled=not can_manage_caasm_alerts,
                    key="resolve_selected_caasm_alert",
                ):
                    changed = resolve_alert(
                        int(selected_caasm_alert["id"]),
                        actor=str(alert_actor),
                        resolution_note=resolution_note,
                    )

                    if changed:
                        demo_success(
                            "The selected alert was resolved."
                        )
                        st.rerun()
                    else:
                        demo_warning(
                            "The selected alert could not be resolved."
                        )

        else:
            demo_info(
                "No persistent correlated-exposure alerts "
                "have been created."
            )

        st.subheader("Identity Risk Table")

        if identities:
            axonius_identity_df = pd.DataFrame(identities)

            axonius_identity_df = axonius_identity_df.sort_values(
                by="risk_score",
                ascending=False
            )

            demo_dataframe(
                axonius_identity_df,
                width="stretch"
            )

            st.subheader("Identity Risk Analytics")

            identity_metric_col1, identity_metric_col2 = st.columns(2)

            with identity_metric_col1:
                demo_write("Identity Risk Scores")
                st.bar_chart(
                    axonius_identity_df.set_index("username")[
                        "risk_score"
                    ]
                )

            with identity_metric_col2:
                demo_write("Identity Type Distribution")
                st.bar_chart(
                    axonius_identity_df[
                        "identity_type"
                    ].value_counts()
                )

        else:
            demo_info("No Axonius identity records are available.")

        st.subheader("Identity Governance Dashboard")

        identity_col1, identity_col2, identity_col3 = st.columns(3)

        identity_col1.metric(
            "Privileged Accounts",
            identity_governance_metrics.get("Privileged Accounts", 0)
        )

        identity_col2.metric(
            "Orphaned Accounts",
            identity_governance_metrics.get("Orphaned Accounts", 0)
        )

        identity_col3.metric(
            "MFA Exceptions",
            identity_governance_metrics.get("MFA Exceptions", 0)
        )

        identity_col4, identity_col5, identity_col6 = st.columns(3)

        identity_col4.metric(
            "Privileged Without MFA",
            identity_governance_metrics.get("Privileged Without MFA", 0)
        )

        identity_col5.metric(
            "High-Risk Identities",
            identity_governance_metrics.get("High-Risk Identities", 0)
        )

        identity_col6.metric(
            "Identity Compliance Rate %",
            identity_governance_metrics.get("Identity Compliance Rate %", 0)
        )

        if identity_governance_rows:
            identity_governance_df = pd.DataFrame(
                identity_governance_rows
            )

            st.subheader("Identity Governance Exceptions")

            demo_dataframe(
                identity_governance_df,
                width="stretch"
            )

            st.subheader("Identity Risk Scores")

            st.bar_chart(
                identity_governance_df.set_index("Username")[
                    "Risk Score"
                ]
            )

            identity_governance_csv = (
                identity_governance_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Identity Governance CSV",
                data=identity_governance_csv,
                file_name="dgs_sentinel_identity_governance.csv",
                mime="text/csv"
            )

        else:
            demo_info("No identity-governance records are available.")

        st.subheader("Coverage Gap Dashboard")

        coverage_col1, coverage_col2, coverage_col3 = st.columns(3)

        coverage_col1.metric(
            "Connected Sources",
            coverage_gap_metrics.get("Connected Sources", 0)
        )

        coverage_col2.metric(
            "Disconnected Sources",
            coverage_gap_metrics.get("Disconnected Sources", 0)
        )

        coverage_col3.metric(
            "Average Coverage %",
            coverage_gap_metrics.get("Average Coverage %", 0)
        )

        coverage_col4, coverage_col5 = st.columns(2)

        coverage_col4.metric(
            "Total Sources",
            coverage_gap_metrics.get("Total Sources", 0)
        )

        coverage_col5.metric(
            "Critical Coverage Gaps",
            coverage_gap_metrics.get("Critical Coverage Gaps", 0)
        )

        if coverage_gap_findings:
            coverage_gap_df = pd.DataFrame(
                coverage_gap_findings
            )

            st.subheader("Connector Coverage Findings")

            demo_dataframe(
                coverage_gap_df,
                width="stretch"
            )

            st.subheader("Coverage Percentage by Source")

            st.bar_chart(
                coverage_gap_df.set_index("Source")[
                    "Coverage %"
                ]
            )

            st.subheader("Connector Priority Distribution")

            st.bar_chart(
                coverage_gap_df["Priority"].value_counts()
            )

            coverage_gap_csv = (
                coverage_gap_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Coverage Gap Findings CSV",
                data=coverage_gap_csv,
                file_name="dgs_sentinel_caasm_coverage_gaps.csv",
                mime="text/csv"
            )

        else:
            demo_success("No connector coverage gaps detected.")

        st.subheader("CAASM Policy and Coverage Findings")

        if policy_findings:
            caasm_findings_df = pd.DataFrame(policy_findings)

            finding_col1, finding_col2, finding_col3 = st.columns(3)

            finding_col1.metric(
                "Total Policy Findings",
                len(caasm_findings_df)
            )

            finding_col2.metric(
                "Critical Findings",
                len(
                    caasm_findings_df[
                        caasm_findings_df["Priority"] == "CRITICAL"
                    ]
                )
            )

            finding_col3.metric(
                "High Findings",
                len(
                    caasm_findings_df[
                        caasm_findings_df["Priority"] == "HIGH"
                    ]
                )
            )

            demo_dataframe(
                caasm_findings_df,
                width="stretch"
            )

            st.subheader("CAASM Findings by Category")

            st.bar_chart(
                caasm_findings_df["Category"].value_counts()
            )

            caasm_csv = (
                caasm_findings_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download CAASM Policy Findings CSV",
                data=caasm_csv,
                file_name="dgs_sentinel_caasm_policy_findings.csv",
                mime="text/csv"
            )

        else:
            demo_success("No CAASM policy or coverage findings detected.")

        st.subheader("CAASM Snapshot History")

        from caasm_snapshot_engine import (
            save_caasm_snapshot,
            load_caasm_snapshots
        )

        can_save_caasm_snapshot = has_permission(
            st.session_state.get("user_role"),
            PERMISSION_RUN_SCANS,
        )

        if st.button(
            "Save Current CAASM Snapshot",
            disabled=not can_save_caasm_snapshot,
        ):
            if not can_save_caasm_snapshot:
                st.error(
                    "Your role is not authorized to save CAASM snapshots."
                )
            else:
                snapshot_path = save_caasm_snapshot(
                    connector_mode=connector_mode,
                    metrics=metrics,
                    identity_governance_metrics=identity_governance_metrics,
                    coverage_gap_metrics=coverage_gap_metrics,
                    policy_findings=policy_findings,
                    coverage_gap_findings=coverage_gap_findings,
                    correlation_metrics=correlation_metrics,
                    correlation_rows=correlation_rows
                )

                demo_success(f"CAASM snapshot saved: {snapshot_path}")

        caasm_snapshots = load_caasm_snapshots()

        if caasm_snapshots:
            caasm_trend_rows = []

            for snapshot in caasm_snapshots:
                snapshot_metrics = snapshot.get("metrics", {})
                identity_metrics = snapshot.get(
                    "identity_governance_metrics",
                    {}
                )
                coverage_metrics = snapshot.get(
                    "coverage_gap_metrics",
                    {}
                )
                snapshot_correlation_metrics = snapshot.get(
                    "correlation_metrics",
                    {}
                )

                caasm_trend_rows.append({
                    "Scan Time": snapshot.get("scan_time"),
                    "CAASM Score": snapshot_metrics.get("CAASM Score", 0),
                    "Asset Coverage %": snapshot_metrics.get("Asset Coverage %", 0),
                    "MFA Coverage %": snapshot_metrics.get("MFA Coverage %", 0),
                    "Unmanaged Assets": snapshot_metrics.get("Unmanaged Assets", 0),
                    "Orphaned Accounts": identity_metrics.get("Orphaned Accounts", 0),
                    "Privileged Without MFA": identity_metrics.get("Privileged Without MFA", 0),
                    "Critical Coverage Gaps": coverage_metrics.get("Critical Coverage Gaps", 0),
                    "Critical Correlations": snapshot_correlation_metrics.get(
                        "Critical Correlations",
                        0
                    ),
                    "High Correlations": snapshot_correlation_metrics.get(
                        "High Correlations",
                        0
                    ),
                    "Average Correlated Risk Score": snapshot_correlation_metrics.get(
                        "Average Correlated Risk Score",
                        0
                    ),
                    "Unmatched Asset Owners": snapshot_correlation_metrics.get(
                        "Unmatched Asset Owners",
                        0
                    ),
                    "Snapshot File": snapshot.get("snapshot_file")
                })

            caasm_trend_df = pd.DataFrame(caasm_trend_rows)

            caasm_trend_df["Scan Time"] = pd.to_datetime(
                caasm_trend_df["Scan Time"],
                errors="coerce",
                utc=True
            )

            caasm_trend_df = caasm_trend_df.dropna(
                subset=["Scan Time"]
            ).sort_values("Scan Time")

            st.subheader("CAASM Risk Delta Summary")

            if len(caasm_trend_df) >= 2:
                latest_caasm = caasm_trend_df.iloc[-1]
                previous_caasm = caasm_trend_df.iloc[-2]

                caasm_score_delta = round(
                    latest_caasm["CAASM Score"]
                    - previous_caasm["CAASM Score"],
                    2
                )

                asset_coverage_delta = round(
                    latest_caasm["Asset Coverage %"]
                    - previous_caasm["Asset Coverage %"],
                    2
                )

                mfa_coverage_delta = round(
                    latest_caasm["MFA Coverage %"]
                    - previous_caasm["MFA Coverage %"],
                    2
                )

                unmanaged_assets_delta = int(
                    latest_caasm["Unmanaged Assets"]
                    - previous_caasm["Unmanaged Assets"]
                )

                orphaned_accounts_delta = int(
                    latest_caasm["Orphaned Accounts"]
                    - previous_caasm["Orphaned Accounts"]
                )

                critical_gap_delta = int(
                    latest_caasm["Critical Coverage Gaps"]
                    - previous_caasm["Critical Coverage Gaps"]
                )

                critical_correlation_delta = int(
                    latest_caasm["Critical Correlations"]
                    - previous_caasm["Critical Correlations"]
                )

                average_correlation_risk_delta = round(
                    latest_caasm["Average Correlated Risk Score"]
                    - previous_caasm["Average Correlated Risk Score"],
                    2
                )

                unmatched_owner_delta = int(
                    latest_caasm["Unmatched Asset Owners"]
                    - previous_caasm["Unmatched Asset Owners"]
                )

                delta_col1, delta_col2, delta_col3 = st.columns(3)

                delta_col1.metric(
                    "CAASM Score Change",
                    caasm_score_delta
                )

                delta_col2.metric(
                    "Asset Coverage Change",
                    f"{asset_coverage_delta}%"
                )

                delta_col3.metric(
                    "MFA Coverage Change",
                    f"{mfa_coverage_delta}%"
                )

                delta_col4, delta_col5, delta_col6 = st.columns(3)

                delta_col4.metric(
                    "Unmanaged Assets Change",
                    unmanaged_assets_delta
                )

                delta_col5.metric(
                    "Orphaned Accounts Change",
                    orphaned_accounts_delta
                )

                delta_col6.metric(
                    "Critical Coverage Gaps Change",
                    critical_gap_delta
                )

                correlation_delta_col1, correlation_delta_col2, correlation_delta_col3 = (
                    st.columns(3)
                )

                correlation_delta_col1.metric(
                    "Critical Correlations Change",
                    critical_correlation_delta
                )

                correlation_delta_col2.metric(
                    "Average Correlated Risk Change",
                    average_correlation_risk_delta
                )

                correlation_delta_col3.metric(
                    "Unmatched Owners Change",
                    unmatched_owner_delta
                )

                demo_caption(
                    "Positive CAASM, asset-coverage, and MFA-coverage changes "
                    "represent improvement. Negative unmanaged-asset, orphaned-account, "
                    "coverage-gap, correlation-risk, and unmatched-owner changes "
                    "represent improvement."
                )

            else:
                demo_info(
                    "Save at least two CAASM snapshots to calculate risk deltas."
                )

            st.subheader("CAASM Score Trend")

            st.line_chart(
                caasm_trend_df.set_index("Scan Time")[
                    [
                        "CAASM Score",
                        "Asset Coverage %",
                        "MFA Coverage %"
                    ]
                ]
            )

            st.subheader("CAASM Risk Trend")

            st.line_chart(
                caasm_trend_df.set_index("Scan Time")[
                    [
                        "Unmanaged Assets",
                        "Orphaned Accounts",
                        "Privileged Without MFA",
                        "Critical Coverage Gaps"
                    ]
                ]
            )

            st.subheader("Correlated Exposure Trend")

            st.line_chart(
                caasm_trend_df.set_index("Scan Time")[
                    [
                        "Critical Correlations",
                        "High Correlations",
                        "Average Correlated Risk Score",
                        "Unmatched Asset Owners"
                    ]
                ]
            )

            st.subheader("CAASM Snapshot Table")

            demo_dataframe(
                caasm_trend_df,
                width="stretch"
            )

            st.subheader("CAASM Snapshot Download Center")

            from pathlib import Path

            caasm_snapshot_dir = Path("caasm_snapshots")

            snapshot_files = sorted(
                caasm_snapshot_dir.glob("caasm_snapshot_*.json"),
                key=lambda file_path: file_path.stat().st_mtime,
                reverse=True
            )

            if snapshot_files:
                selected_caasm_snapshot = st.selectbox(
                    "Select CAASM snapshot to download",
                    [file_path.name for file_path in snapshot_files],
                    key="caasm_snapshot_download_select"
                )

                selected_caasm_snapshot_path = (
                    caasm_snapshot_dir / selected_caasm_snapshot
                )

                with open(selected_caasm_snapshot_path, "rb") as snapshot_file:
                    demo_download_button(
                        label="Download Selected CAASM Snapshot JSON",
                        data=snapshot_file.read(),
                        file_name=selected_caasm_snapshot,
                        mime="application/json"
                    )

            if len(caasm_trend_df) >= 2:
                latest_comparison = caasm_trend_df.iloc[-1]
                previous_comparison = caasm_trend_df.iloc[-2]

                comparison_rows = [
                    {
                        "Metric": "CAASM Score",
                        "Previous": previous_comparison["CAASM Score"],
                        "Latest": latest_comparison["CAASM Score"],
                        "Change": round(
                            latest_comparison["CAASM Score"]
                            - previous_comparison["CAASM Score"],
                            2
                        )
                    },
                    {
                        "Metric": "Asset Coverage %",
                        "Previous": previous_comparison["Asset Coverage %"],
                        "Latest": latest_comparison["Asset Coverage %"],
                        "Change": round(
                            latest_comparison["Asset Coverage %"]
                            - previous_comparison["Asset Coverage %"],
                            2
                        )
                    },
                    {
                        "Metric": "MFA Coverage %",
                        "Previous": previous_comparison["MFA Coverage %"],
                        "Latest": latest_comparison["MFA Coverage %"],
                        "Change": round(
                            latest_comparison["MFA Coverage %"]
                            - previous_comparison["MFA Coverage %"],
                            2
                        )
                    },
                    {
                        "Metric": "Unmanaged Assets",
                        "Previous": previous_comparison["Unmanaged Assets"],
                        "Latest": latest_comparison["Unmanaged Assets"],
                        "Change": int(
                            latest_comparison["Unmanaged Assets"]
                            - previous_comparison["Unmanaged Assets"]
                        )
                    },
                    {
                        "Metric": "Orphaned Accounts",
                        "Previous": previous_comparison["Orphaned Accounts"],
                        "Latest": latest_comparison["Orphaned Accounts"],
                        "Change": int(
                            latest_comparison["Orphaned Accounts"]
                            - previous_comparison["Orphaned Accounts"]
                        )
                    },
                    {
                        "Metric": "Critical Coverage Gaps",
                        "Previous": previous_comparison["Critical Coverage Gaps"],
                        "Latest": latest_comparison["Critical Coverage Gaps"],
                        "Change": int(
                            latest_comparison["Critical Coverage Gaps"]
                            - previous_comparison["Critical Coverage Gaps"]
                        )
                    },
                    {
                        "Metric": "Critical Correlations",
                        "Previous": previous_comparison["Critical Correlations"],
                        "Latest": latest_comparison["Critical Correlations"],
                        "Change": int(
                            latest_comparison["Critical Correlations"]
                            - previous_comparison["Critical Correlations"]
                        )
                    },
                    {
                        "Metric": "High Correlations",
                        "Previous": previous_comparison["High Correlations"],
                        "Latest": latest_comparison["High Correlations"],
                        "Change": int(
                            latest_comparison["High Correlations"]
                            - previous_comparison["High Correlations"]
                        )
                    },
                    {
                        "Metric": "Average Correlated Risk Score",
                        "Previous": previous_comparison[
                            "Average Correlated Risk Score"
                        ],
                        "Latest": latest_comparison[
                            "Average Correlated Risk Score"
                        ],
                        "Change": round(
                            latest_comparison[
                                "Average Correlated Risk Score"
                            ]
                            - previous_comparison[
                                "Average Correlated Risk Score"
                            ],
                            2
                        )
                    },
                    {
                        "Metric": "Unmatched Asset Owners",
                        "Previous": previous_comparison[
                            "Unmatched Asset Owners"
                        ],
                        "Latest": latest_comparison[
                            "Unmatched Asset Owners"
                        ],
                        "Change": int(
                            latest_comparison["Unmatched Asset Owners"]
                            - previous_comparison["Unmatched Asset Owners"]
                        )
                    }
                ]

                caasm_comparison_df = pd.DataFrame(comparison_rows)

                st.subheader("Latest Snapshot vs Previous Snapshot")

                demo_dataframe(
                    caasm_comparison_df,
                    width="stretch"
                )

                caasm_comparison_csv = (
                    caasm_comparison_df
                    .to_csv(index=False)
                    .encode("utf-8")
                )

                demo_download_button(
                    label="Download CAASM Comparison CSV",
                    data=caasm_comparison_csv,
                    file_name="dgs_sentinel_caasm_snapshot_comparison.csv",
                    mime="text/csv"
                )

            else:
                demo_info(
                    "Save at least two CAASM snapshots to export a comparison."
                )

        else:
            demo_info(
                "No CAASM snapshots found yet. Save a snapshot to begin trending."
            )

        st.subheader("Executive CAASM Recommendations")

        if executive_recommendations:
            executive_recommendations_df = pd.DataFrame(
                executive_recommendations
            )

            demo_dataframe(
                executive_recommendations_df,
                width="stretch"
            )

            executive_recommendations_csv = (
                executive_recommendations_df
                .to_csv(index=False)
                .encode("utf-8")
            )

            demo_download_button(
                label="Download Executive CAASM Recommendations CSV",
                data=executive_recommendations_csv,
                file_name="dgs_sentinel_caasm_executive_recommendations.csv",
                mime="text/csv"
            )

        else:
            demo_info("No executive CAASM recommendations available.")

        st.subheader("Executive CAASM Export")

        caasm_pdf_buffer = generate_caasm_pdf(
            connector_mode=connector_mode,
            metrics=metrics,
            identity_governance_metrics=identity_governance_metrics,
            coverage_gap_metrics=coverage_gap_metrics,
            policy_findings=policy_findings,
            coverage_gap_findings=coverage_gap_findings,
            executive_recommendations=executive_recommendations
        )

        demo_download_button(
            label="Download Executive CAASM PDF Report",
            data=caasm_pdf_buffer,
            file_name="dgs_sentinel_executive_caasm_report.pdf",
            mime="application/pdf"
        )

    except Exception as e:
        st.error(f"Unable to load Axonius CAASM analytics: {e}")



if page == "Ask Sentinel AI":

    from sentinel_ai_analyst import (
        build_security_context,
        calculate_analyst_metrics,
        generate_local_analyst_response,
        generate_executive_security_summary,
        get_available_clients,
        generate_client_security_summary,
        generate_client_analyst_response,
        compare_clients_by_combined_risk
    )

    st.title("Ask Sentinel AI")
    demo_caption(
        "Grounded cloud-security and CAASM analysis based on saved DGS Sentinel AI platform data"
    )

    demo_info(
        "This analyst currently uses local platform data only. "
        "It does not modify AWS resources."
    )

    analyst_context = build_security_context()
    analyst_metrics = calculate_analyst_metrics(
        analyst_context
    )

    st.subheader("Analyst Data Coverage")

    coverage_col1, coverage_col2, coverage_col3 = st.columns(3)

    coverage_col1.metric(
        "Assets Loaded",
        analyst_metrics.get("Total Assets", 0)
    )

    coverage_col2.metric(
        "Open Remediation Items",
        analyst_metrics.get("Open Remediation Items", 0)
    )

    coverage_col3.metric(
        "CAASM Snapshots",
        analyst_context.get("caasm_snapshot_count", 0)
    )

    st.subheader("Client Context")

    available_clients = get_available_clients()

    client_options = ["All Saved Data"] + [
        sanitize_text(
            f"{client.get('client_name')} | {client.get('aws_account_id')}"
        )
        for client in available_clients
    ]

    selected_client_context = st.selectbox(
        "Select analyst context",
        client_options
    )

    selected_client = None

    if selected_client_context != "All Saved Data":
        selected_client_index = client_options.index(
            selected_client_context
        ) - 1

        selected_client = available_clients[
            selected_client_index
        ]

        demo_info(
            f"Analyst context selected: "
            f"{selected_client.get('client_name')} "
            f"({selected_client.get('aws_account_id')})"
        )

    st.subheader("Executive Client Risk Ranking")

    client_risk_rows = compare_clients_by_combined_risk()

    if client_risk_rows:
        client_risk_df = pd.DataFrame(
            client_risk_rows
        )

        demo_dataframe(
            client_risk_df,
            width="stretch"
        )

        ranking_col1, ranking_col2, ranking_col3 = st.columns(3)

        highest_risk_client = client_risk_df.iloc[0]

        ranking_col1.metric(
            "Highest-Risk Client",
            highest_risk_client["Client"]
        )

        ranking_col2.metric(
            "Highest Combined Risk Score",
            highest_risk_client["Combined Risk Score"]
        )

        ranking_col3.metric(
            "Open Remediation Items",
            int(
                client_risk_df["Open Remediation"].sum()
            )
        )

        client_risk_csv = (
            client_risk_df
            .to_csv(index=False)
            .encode("utf-8")
        )

        demo_download_button(
            label="Download Client Risk Ranking CSV",
            data=client_risk_csv,
            file_name="dgs_sentinel_client_risk_ranking.csv",
            mime="text/csv"
        )

        demo_caption(
            "Combined risk ranking uses saved asset exposure and "
            "client-specific remediation findings."
        )

    else:
        demo_info(
            "No saved client-risk ranking data is available. "
            "Run client scans first."
        )

    st.subheader("Ask a Security Question")

    question_templates = [
        "Custom Question",
        "What are my top risks?",
        "Which client has the highest risk?",
        "What should I fix first?",
        "Summarize my CAASM posture.",
        "What changed since the last CAASM snapshot?",
        "What identity risks need attention?",
        "Which remediation items are critical?",
        "What security-tool coverage gaps should leadership address?"
    ]

    selected_template = st.selectbox(
        "Choose a question template",
        question_templates
    )

    default_question = (
        ""
        if selected_template == "Custom Question"
        else selected_template
    )

    question = st.text_area(
        "Enter your question",
        value=default_question,
        placeholder=(
            "Examples:\n"
            "What are my top risks?\n"
            "What should I fix first?\n"
            "Summarize my CAASM posture.\n"
            "What identity risks need attention?"
        ),
        height=140
    )

    if st.button(
        "Analyze Security Posture",
        type="primary"
    ):
        if question.strip():
            with st.spinner("Analyzing saved platform data..."):
                if selected_client:
                    analyst_response = generate_client_analyst_response(
                        question=question,
                        client_name=selected_client.get("client_name"),
                        aws_account_id=selected_client.get("aws_account_id")
                    )

                else:
                    analyst_response = generate_local_analyst_response(
                        question
                    )

            st.subheader("Sentinel AI Analyst Response")

            st.text_area(
                "Grounded analysis",
                value=analyst_response,
                height=500
            )

            demo_download_button(
                label="Download Analyst Response",
                data=analyst_response.encode("utf-8"),
                file_name="dgs_sentinel_ai_analyst_response.txt",
                mime="text/plain"
            )

        else:
            demo_warning("Enter a security question before running the analyst.")

    st.subheader("OpenAI Executive Narrative")

    from sentinel_ai_openai import (
        openai_configured,
        generate_openai_executive_narrative
    )

    if openai_configured():
        demo_success(
            "OpenAI narrative layer is configured. "
            "Grounded DGS Sentinel AI platform data will be used."
        )
    else:
        demo_info(
            "OpenAI narrative layer is not configured. "
            "The local grounded analyst remains available."
        )

    if st.button("Generate OpenAI Executive Narrative"):
        with st.spinner(
            "Generating grounded executive narrative..."
        ):
            narrative_result = (
                generate_openai_executive_narrative()
            )

        if narrative_result.get("success"):
            narrative_text = narrative_result.get(
                "narrative",
                ""
            )

            demo_success(
                "OpenAI executive narrative generated successfully."
            )

            st.text_area(
                "CISO-level executive narrative",
                value=narrative_text,
                height=650
            )

            demo_download_button(
                label="Download OpenAI Executive Narrative",
                data=narrative_text.encode("utf-8"),
                file_name=(
                    "dgs_sentinel_openai_executive_narrative.txt"
                ),
                mime="text/plain"
            )

        else:
            demo_warning(
                "OpenAI narrative generation was unavailable. "
                "The local grounded analyst remains active."
            )

            st.error(
                narrative_result.get(
                    "message",
                    "Unknown OpenAI narrative error."
                )
            )

    st.subheader("Executive Summary Export")

    executive_summary = generate_executive_security_summary()

    demo_download_button(
        label="Download Executive Security Summary",
        data=executive_summary.encode("utf-8"),
        file_name="dgs_sentinel_ai_executive_security_summary.txt",
        mime="text/plain"
    )

    with st.expander("Preview Executive Security Summary"):
        st.text(executive_summary)

    if selected_client:
        st.subheader("Selected Client PDF Export")

        from client_analyst_report import (
            generate_client_analyst_pdf
        )

        client_pdf_buffer = generate_client_analyst_pdf(
            client_name=selected_client.get("client_name"),
            aws_account_id=selected_client.get("aws_account_id")
        )

        safe_client_name = (
            selected_client.get("client_name", "client")
            .lower()
            .replace(" ", "_")
        )

        demo_download_button(
            label="Download Selected Client Security Report PDF",
            data=client_pdf_buffer,
            file_name=(
                f"dgs_sentinel_{safe_client_name}_security_report.pdf"
            ),
            mime="application/pdf"
        )

        demo_caption(
            "The selected-client report is generated from saved read-only "
            "assessment data for the selected AWS account."
        )

    st.subheader("Suggested Questions")

    demo_markdown(
        """
        - What are my top risks?
        - What should I fix first?
        - Summarize my CAASM posture.
        - What identity risks need attention?
        - Which remediation items are critical?
        - What security-tool coverage gaps should leadership address?
        """
    )


if page == "Client Accounts":

    can_manage_clients = has_permission(
        st.session_state.get("user_role"),
        PERMISSION_MANAGE_CLIENTS,
    )

    if not can_manage_clients:
        st.error(
            "Your role is not authorized to manage client accounts."
        )
        st.stop()

    st.title("🛡️ DGS Sentinel AI")
    demo_caption("Client Account Management")

    st.header("Client Account Management")

    demo_markdown(
        "Register AWS accounts or Azure subscriptions for multicloud "
        "security visibility."
    )

    if add_client is None or get_clients is None:
        st.error(
            "Client database module is unavailable. Confirm client_db.py exists and imports correctly."
        )
        st.stop()

    cloud_provider = st.selectbox(
        "Cloud Provider",
        ["AWS", "Azure"],
        key="client_cloud_provider",
    )

    with st.form("client_account_form"):
        client_name = st.text_input("Client Name")

        aws_account_id = None
        role_arn = None
        azure_subscription_id = None
        azure_tenant_id = None
        azure_client_id = None

        if cloud_provider == "AWS":
            aws_account_id = st.text_input("AWS Account ID")
            role_arn = st.text_input("AWS Role ARN")
        else:
            azure_subscription_id = st.text_input(
                "Azure Subscription ID"
            )
            azure_tenant_id = st.text_input("Azure Tenant ID")
            azure_client_id = st.text_input(
                "Azure Application (Client) ID"
            )

        environment = st.selectbox(
            "Environment",
            [
                "Production",
                "Development",
                "Testing",
                "Sandbox"
            ]
        )

        submitted = st.form_submit_button("Add Client Account")

        if submitted:
            provider_fields_complete = (
                aws_account_id and role_arn
                if cloud_provider == "AWS"
                else (
                    azure_subscription_id
                    and azure_tenant_id
                    and azure_client_id
                )
            )

            if client_name and provider_fields_complete:
                add_client(
                    client_name=client_name,
                    aws_account_id=aws_account_id,
                    role_arn=role_arn,
                    environment=environment,
                    cloud_provider=cloud_provider,
                    azure_subscription_id=azure_subscription_id,
                    azure_tenant_id=azure_tenant_id,
                    azure_client_id=azure_client_id,
                )
                demo_success(
                    f"{cloud_provider} client account added successfully."
                )
            else:
                st.error("Please complete all required fields.")

    st.subheader("Saved Client Accounts")

    clients = get_clients()

    if clients:
        clients_df = pd.DataFrame(
            clients,
            columns=[
                "ID",
                "Client Name",
                "AWS Account ID",
                "Role ARN",
                "Environment",
                "Cloud Provider",
                "Azure Subscription ID",
                "Azure Tenant ID",
                "Azure Client ID",
            ]
        )

        demo_dataframe(
            clients_df,
            width="stretch"
        )
    else:
        demo_info("No client accounts saved yet.")

    st.stop()



# ============================================================
# ACTIVE CLIENT SELECTOR
# ============================================================

selected_client = None
selected_client_data = None

if get_clients is not None:

    saved_clients = get_clients()

    if saved_clients:

        client_options = [
            "DGS Internal / Default AWS Account"
        ] + [
            (
                f"{client[1]} | "
                f"{client[6] if str(client[5] or 'AWS').upper() == 'AZURE' else client[2]} "
                f"| {client[4]}"
            )
            for client in saved_clients
        ]

        selected_client = st.sidebar.selectbox(
            "Active Client Account",
            client_options,
            key="active_client_selector"
        )

        if selected_client != "DGS Internal / Default AWS Account":

            selected_index = (
                client_options.index(selected_client) - 1
            )

            selected_client_data = saved_clients[selected_index]

            st.sidebar.success(
                f"Client Selected: {selected_client_data[1]}"
            )

            

        else:
            st.sidebar.info(
                "Using default DGS AWS account."
            )

    else:
        st.sidebar.info(
            "No client accounts saved yet."
        )

else:
    st.sidebar.warning(
        "Client database unavailable."
    )

# ============================================================
# TEST CLIENT CLOUD CONNECTION
# ============================================================

if selected_client_data is not None:

    selected_provider = (
        str(selected_client_data[5] or "AWS").strip().upper()
    )

    if selected_provider == "AZURE":
        azure_secret = st.sidebar.text_input(
            "Azure Client Secret",
            type="password",
            key="azure_connection_client_secret",
            help=(
                "Used only for this connection test. "
                "The secret is not stored in the client database."
            ),
        )

        if st.sidebar.button(
            "Test Client Azure Connection",
            key="test_azure_client_connection",
        ):
            if test_azure_subscription is None:
                st.sidebar.error(
                    "Azure validation module is unavailable."
                )
            elif not azure_secret:
                st.sidebar.error(
                    "Enter the Azure client secret before testing."
                )
            else:
                try:
                    identity = test_azure_subscription(
                        tenant_id=selected_client_data[7],
                        client_id=selected_client_data[8],
                        client_secret=azure_secret,
                        subscription_id=selected_client_data[6],
                    )

                    st.sidebar.success(
                        "Connected to Azure Subscription: "
                        f"{identity['display_name']} "
                        f"({identity['subscription_id']})"
                    )

                except Exception as exc:
                    logger.exception(
                        "Azure client connection test failed."
                    )
                    st.sidebar.error(
                        f"Azure connection test failed: {exc}"
                    )

        if st.sidebar.button(
            "Run Azure Resource Discovery",
            key="run_azure_resource_discovery",
        ):
            if discover_azure_resources is None:
                st.sidebar.error(
                    "Azure resource discovery module is unavailable."
                )
            elif not azure_secret:
                st.sidebar.error(
                    "Enter the Azure client secret before discovery."
                )
            else:
                try:
                    credential = create_azure_credential(
                        tenant_id=selected_client_data[7],
                        client_id=selected_client_data[8],
                        client_secret=azure_secret,
                    )

                    discovery_result = discover_azure_resources(
                        credential=credential,
                        subscription_id=selected_client_data[6],
                    )

                    st.session_state[
                        "azure_resource_discovery"
                    ] = discovery_result
                    st.session_state[
                        "azure_resource_discovery_client"
                    ] = selected_client_data[1]

                    if analyze_storage_exposure is not None:
                        storage_exposure = analyze_storage_exposure(
                            discovery_result.get(
                                "storage_accounts",
                                [],
                            )
                        )

                        st.session_state[
                            "azure_storage_exposure"
                        ] = storage_exposure
                        st.session_state[
                            "azure_storage_exposure_client"
                        ] = selected_client_data[1]
                    else:
                        st.session_state.pop(
                            "azure_storage_exposure",
                            None,
                        )
                        st.session_state.pop(
                            "azure_storage_exposure_client",
                            None,
                        )

                    if analyze_azure_network_exposure is not None:
                        network_exposure = (
                            analyze_azure_network_exposure(
                                network_security_groups=(
                                    discovery_result.get(
                                        "network_security_groups",
                                        [],
                                    )
                                ),
                                public_ip_addresses=(
                                    discovery_result.get(
                                        "public_ip_addresses",
                                        [],
                                    )
                                ),
                                network_interfaces=(
                                    discovery_result.get(
                                        "network_interfaces",
                                        [],
                                    )
                                ),
                                virtual_machines=(
                                    discovery_result.get(
                                        "virtual_machines",
                                        [],
                                    )
                                ),
                            )
                        )

                        st.session_state[
                            "azure_network_exposure"
                        ] = network_exposure
                        st.session_state[
                            "azure_network_exposure_client"
                        ] = selected_client_data[1]
                    else:
                        st.session_state.pop(
                            "azure_network_exposure",
                            None,
                        )
                        st.session_state.pop(
                            "azure_network_exposure_client",
                            None,
                        )

                    discovery_status = str(
                        discovery_result.get(
                            "discovery_status",
                            "COMPLETE",
                        )
                    ).strip().upper()

                    discovery_errors = discovery_result.get(
                        "errors",
                        [],
                    )

                    if discovery_status == "PARTIAL":
                        st.sidebar.warning(
                            "Azure discovery completed with "
                            f"{len(discovery_errors)} partial "
                            "failure(s). Available results were "
                            "preserved."
                        )
                    else:
                        st.sidebar.success(
                            "Azure resource discovery completed."
                        )

                except Exception as exc:
                    logger.exception(
                        "Azure resource discovery failed."
                    )
                    st.sidebar.error(
                        f"Azure discovery failed: {exc}"
                    )

        azure_security_location = st.sidebar.text_input(
            "Defender for Cloud Location",
            value="centralus",
            key="azure_security_center_location",
            help=(
                "Azure Security Center location used by the "
                "Defender for Cloud management API."
            ),
        )

        if st.sidebar.button(
            "Run Azure Security Posture",
            key="run_azure_security_posture",
        ):
            if discover_azure_security_posture is None:
                st.sidebar.error(
                    "Azure security posture module is unavailable."
                )
            elif create_azure_credential is None:
                st.sidebar.error(
                    "Azure credential module is unavailable."
                )
            elif not azure_secret:
                st.sidebar.error(
                    "Enter the Azure client secret before scanning."
                )
            elif not azure_security_location:
                st.sidebar.error(
                    "Enter the Defender for Cloud location."
                )
            else:
                try:
                    credential = create_azure_credential(
                        tenant_id=selected_client_data[7],
                        client_id=selected_client_data[8],
                        client_secret=azure_secret,
                    )

                    posture_result = (
                        discover_azure_security_posture(
                            credential=credential,
                            subscription_id=selected_client_data[6],
                            asc_location=azure_security_location,
                        )
                    )

                    st.session_state[
                        "azure_security_posture"
                    ] = posture_result
                    st.session_state[
                        "azure_security_posture_client"
                    ] = selected_client_data[1]

                    posture_status = str(
                        posture_result.get(
                            "discovery_status",
                            "COMPLETE",
                        )
                    ).strip().upper()

                    posture_errors = posture_result.get(
                        "errors",
                        [],
                    )

                    if posture_status == "PARTIAL":
                        st.sidebar.warning(
                            "Azure security posture completed with "
                            f"{len(posture_errors)} partial "
                            "failure(s). Available Defender results "
                            "were preserved."
                        )
                    elif posture_status == "FAILED":
                        st.sidebar.error(
                            "Azure security posture discovery failed "
                            "for all Defender components."
                        )
                    else:
                        st.sidebar.success(
                            "Azure security posture discovery completed."
                        )

                except Exception as exc:
                    logger.exception(
                        "Azure security posture discovery failed."
                    )
                    st.sidebar.error(
                        f"Azure security posture failed: {exc}"
                    )

    else:
        if st.sidebar.button(
            "Test Client AWS Connection",
            key="test_client_connection",
        ):
            role_arn = selected_client_data[3]
            session = assume_client_role(role_arn)

            if session:
                try:
                    sts = session.client("sts")
                    identity = sts.get_caller_identity()

                    st.sidebar.success(
                        "Connected to AWS Account: "
                        f"{identity['Account']}"
                    )

                except Exception as exc:
                    logger.exception(
                        "AWS client connection test failed."
                    )
                    st.sidebar.error(
                        f"Connection test failed: {exc}"
                    )
            else:
                st.sidebar.error(
                    "Unable to assume the selected AWS client role."
                )

else:
    st.sidebar.info(
        "Select a saved client account to enable "
        "the cloud connection test."
    )

# ============================================================
# MAIN DASHBOARD HEADER
# ============================================================

if page != "Dashboard":
    st.stop()

st.title("🛡️ DGS Sentinel AI")
demo_caption("AI-Powered CAASM / CSPM / CNAPP / SIEM Platform")

azure_discovery = st.session_state.get(
    "azure_resource_discovery"
)
azure_network_exposure = st.session_state.get(
    "azure_network_exposure"
)
azure_storage_exposure = st.session_state.get(
    "azure_storage_exposure"
)

azure_display_client_name = "Selected Azure Client"

if (
    demo_mode_enabled()
    and build_azure_demo_dataset is not None
):
    azure_demo_dataset = build_azure_demo_dataset()

    azure_discovery = azure_demo_dataset["discovery"]
    azure_network_exposure = azure_demo_dataset[
        "network_exposure"
    ]
    azure_storage_exposure = azure_demo_dataset[
        "storage_exposure"
    ]
    azure_display_client_name = azure_demo_dataset[
        "client_name"
    ]

    demo_warning(
        "Azure Demo Dataset — Sanitized sample Azure "
        "resources and exposure findings are displayed."
    )

if azure_discovery:
    st.header("Azure Resource Discovery")

    azure_client_name = st.session_state.get(
        "azure_resource_discovery_client",
        azure_display_client_name,
    )

    demo_caption(
        f"Latest Azure discovery results for {azure_client_name}"
    )

    azure_summary = azure_discovery.get("summary", {})

    azure_discovery_status = str(
        azure_discovery.get(
            "discovery_status",
            "COMPLETE",
        )
    ).strip().upper()

    azure_discovery_errors = azure_discovery.get(
        "errors",
        [],
    )

    azure_started_at = azure_discovery.get("started_at")
    azure_completed_at = azure_discovery.get("completed_at")
    azure_service_status = azure_discovery.get(
        "service_status",
        {},
    )

    scan_timestamp_parts = []

    if azure_started_at:
        scan_timestamp_parts.append(
            f"Started: {azure_started_at}"
        )

    if azure_completed_at:
        scan_timestamp_parts.append(
            f"Completed: {azure_completed_at}"
        )

    if scan_timestamp_parts:
        demo_caption(
            " | ".join(scan_timestamp_parts)
        )

    if azure_service_status:
        service_status_rows = []

        for resource_type, status_details in (
            azure_service_status.items()
        ):
            error_details = (
                status_details.get("error") or {}
            )

            service_status_rows.append(
                {
                    "Resource Category": (
                        resource_type.replace(
                            "_",
                            " ",
                        ).title()
                    ),
                    "Status": status_details.get(
                        "status",
                        "UNKNOWN",
                    ),
                    "Resource Count": status_details.get(
                        "resource_count",
                        0,
                    ),
                    "Scanned At": status_details.get(
                        "scanned_at",
                    ),
                    "Error": error_details.get(
                        "message",
                    ),
                }
            )

        complete_service_count = sum(
            row["Status"] == "COMPLETE"
            for row in service_status_rows
        )
        failed_service_count = sum(
            row["Status"] == "FAILED"
            for row in service_status_rows
        )

        (
            service_col1,
            service_col2,
            service_col3,
        ) = st.columns(3)

        service_col1.metric(
            "Services Complete",
            complete_service_count,
        )
        service_col2.metric(
            "Services Failed",
            failed_service_count,
        )
        service_col3.metric(
            "Services Checked",
            len(service_status_rows),
        )

        with st.expander(
            "Azure service discovery status",
            expanded=failed_service_count > 0,
        ):
            demo_dataframe(
                pd.DataFrame(service_status_rows),
                width="stretch",
            )

    if azure_discovery_status == "PARTIAL":
        st.warning(
            "Azure discovery returned partial results. "
            "Resources that were discovered successfully are "
            "shown below."
        )

        with st.expander(
            "View Azure discovery errors",
            expanded=False,
        ):
            if azure_discovery_errors:
                demo_dataframe(
                    pd.DataFrame(azure_discovery_errors),
                    width="stretch",
                )
            else:
                demo_info(
                    "No structured Azure discovery errors "
                    "were returned."
                )

    azure_col1, azure_col2, azure_col3 = st.columns(3)

    azure_col1.metric(
        "Resource Groups",
        azure_summary.get("resource_groups", 0),
    )
    azure_col2.metric(
        "Virtual Machines",
        azure_summary.get("virtual_machines", 0),
    )
    azure_col3.metric(
        "Storage Accounts",
        azure_summary.get("storage_accounts", 0),
    )

    resource_groups = azure_discovery.get(
        "resource_groups",
        [],
    )
    virtual_machines = azure_discovery.get(
        "virtual_machines",
        [],
    )
    storage_accounts = azure_discovery.get(
        "storage_accounts",
        [],
    )

    azure_tab1, azure_tab2, azure_tab3 = st.tabs(
        [
            "Resource Groups",
            "Virtual Machines",
            "Storage Accounts",
        ]
    )

    with azure_tab1:
        if resource_groups:
            demo_dataframe(
                pd.DataFrame(resource_groups),
                width="stretch",
            )
        else:
            demo_info("No Azure resource groups discovered.")

    with azure_tab2:
        if virtual_machines:
            demo_dataframe(
                pd.DataFrame(virtual_machines),
                width="stretch",
            )
        else:
            demo_info("No Azure virtual machines discovered.")

    with azure_tab3:
        if storage_accounts:
            demo_dataframe(
                pd.DataFrame(storage_accounts),
                width="stretch",
            )
        else:
            demo_info("No Azure storage accounts discovered.")

    st.divider()

if azure_network_exposure:
    st.header("Azure Network Exposure Analysis")

    network_client_name = st.session_state.get(
        "azure_network_exposure_client",
        azure_display_client_name,
    )

    demo_caption(
        f"Latest network exposure analysis for "
        f"{network_client_name}"
    )

    network_summary = azure_network_exposure.get(
        "summary",
        {},
    )

    (
        network_col1,
        network_col2,
        network_col3,
        network_col4,
        network_col5,
    ) = st.columns(5)

    network_col1.metric(
        "Network Security Groups",
        network_summary.get(
            "network_security_groups",
            0,
        ),
    )
    network_col2.metric(
        "Exposed NSGs",
        network_summary.get(
            "exposed_network_security_groups",
            0,
        ),
    )
    network_col3.metric(
        "Public IPs",
        network_summary.get(
            "public_ip_addresses",
            0,
        ),
    )
    network_col4.metric(
        "Internet-Facing VMs",
        network_summary.get(
            "internet_facing_virtual_machines",
            0,
        ),
    )
    network_col5.metric(
        "Total Findings",
        network_summary.get(
            "total_findings",
            0,
        ),
    )

    (
        severity_col1,
        severity_col2,
        severity_col3,
        severity_col4,
    ) = st.columns(4)

    severity_col1.metric(
        "Critical Findings",
        network_summary.get(
            "critical_findings",
            0,
        ),
    )
    severity_col2.metric(
        "High Findings",
        network_summary.get(
            "high_findings",
            0,
        ),
    )
    severity_col3.metric(
        "Medium Findings",
        network_summary.get(
            "medium_findings",
            0,
        ),
    )
    severity_col4.metric(
        "Unassigned Public IPs",
        network_summary.get(
            "unassigned_public_ip_addresses",
            0,
        ),
    )

    network_findings = azure_network_exposure.get(
        "findings",
        [],
    )
    network_security_groups = azure_network_exposure.get(
        "network_security_groups",
        [],
    )
    public_ip_addresses = azure_network_exposure.get(
        "public_ip_addresses",
        [],
    )
    analyzed_virtual_machines = azure_network_exposure.get(
        "virtual_machines",
        [],
    )

    high_risk_network_findings = [
        finding
        for finding in network_findings
        if str(
            finding.get("severity", "")
        ).strip().upper() in {"CRITICAL", "HIGH"}
    ]

    exposed_network_security_groups = [
        network_security_group
        for network_security_group in network_security_groups
        if network_security_group.get("internet_exposed")
    ]

    internet_facing_virtual_machines = [
        virtual_machine
        for virtual_machine in analyzed_virtual_machines
        if virtual_machine.get("internet_exposed")
    ]

    (
        network_findings_tab,
        high_risk_network_tab,
        exposed_nsg_tab,
        public_ip_tab,
        internet_vm_tab,
    ) = st.tabs(
        [
            "All Findings",
            "Critical and High Risk",
            "Exposed NSGs",
            "Public IP Addresses",
            "Internet-Facing VMs",
        ]
    )

    with network_findings_tab:
        if network_findings:
            network_findings_df = pd.DataFrame(
                network_findings
            )

            network_severity_order = {
                "CRITICAL": 4,
                "HIGH": 3,
                "MEDIUM": 2,
                "LOW": 1,
            }

            network_findings_df[
                "Severity Rank"
            ] = (
                network_findings_df["severity"]
                .astype(str)
                .str.upper()
                .map(network_severity_order)
                .fillna(0)
            )

            network_findings_df = (
                network_findings_df.sort_values(
                    by="Severity Rank",
                    ascending=False,
                ).drop(
                    columns=["Severity Rank"]
                )
            )

            demo_dataframe(
                network_findings_df,
                width="stretch",
            )
        else:
            demo_success(
                "No Azure network exposure findings "
                "were identified."
            )

    with high_risk_network_tab:
        if high_risk_network_findings:
            demo_dataframe(
                pd.DataFrame(
                    high_risk_network_findings
                ),
                width="stretch",
            )
        else:
            demo_success(
                "No critical or high-risk Azure network "
                "findings were identified."
            )

    with exposed_nsg_tab:
        if exposed_network_security_groups:
            demo_dataframe(
                pd.DataFrame(
                    exposed_network_security_groups
                ),
                width="stretch",
            )
        else:
            demo_success(
                "No internet-exposed network security "
                "groups were identified."
            )

    with public_ip_tab:
        if public_ip_addresses:
            demo_dataframe(
                pd.DataFrame(public_ip_addresses),
                width="stretch",
            )
        else:
            demo_info(
                "No Azure public IP addresses were discovered."
            )

    with internet_vm_tab:
        if internet_facing_virtual_machines:
            demo_dataframe(
                pd.DataFrame(
                    internet_facing_virtual_machines
                ),
                width="stretch",
            )
        else:
            demo_success(
                "No internet-facing Azure virtual machines "
                "were identified."
            )

    st.subheader("Azure NSG Remediation Actions")

    selected_provider = (
        str(selected_client_data[5] or "AWS").strip().upper()
        if selected_client_data is not None
        else ""
    )

    azure_network_action_creation_allowed = has_permission(
        st.session_state.get("user_role"),
        PERMISSION_EXECUTE_REMEDIATION,
    )

    valid_azure_network_binding = (
        selected_client_data is not None
        and selected_provider == "AZURE"
        and bool(selected_client_data[6])
        and bool(selected_client_data[7])
        and bool(selected_client_data[8])
    )

    unique_nsg_rule_targets = {}

    network_severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    for finding in network_findings:
        if (
            finding.get("resource_type")
            != "AZURE_NETWORK_SECURITY_GROUP"
        ):
            continue

        resource_id = str(
            finding.get("resource_id") or ""
        ).strip()
        rule_name = str(
            finding.get("rule_name") or ""
        ).strip()

        if not resource_id or not rule_name:
            continue

        target_key = (resource_id, rule_name)
        severity = str(
            finding.get("severity") or "Medium"
        ).strip()

        existing = unique_nsg_rule_targets.get(target_key)

        if (
            existing is None
            or network_severity_rank.get(
                severity.lower(),
                0,
            )
            > network_severity_rank.get(
                str(existing.get("priority", "")).lower(),
                0,
            )
        ):
            unique_nsg_rule_targets[target_key] = {
                "category": "Azure Network",
                "finding": (
                    f"Azure NSG Risk - {resource_id} "
                    f"| Rule: {rule_name}"
                ),
                "priority": severity.upper(),
            }

    network_remediation_plan = list(
        unique_nsg_rule_targets.values()
    )

    demo_caption(
        "Creates one approval-controlled remediation action per "
        "internet-exposed Azure NSG rule. Duplicate open actions "
        "are reused."
    )

    if demo_mode_enabled():
        demo_info(
            "Action creation is disabled while the sanitized Azure "
            "demo dataset is active."
        )

    elif not azure_network_action_creation_allowed:
        demo_info(
            "Your role is not authorized to create executable "
            "remediation actions."
        )

    elif not valid_azure_network_binding:
        demo_info(
            "Select a saved Azure client with subscription, tenant, "
            "and client IDs before creating NSG remediation actions."
        )

    elif create_actions_from_remediation_plan is None:
        demo_warning(
            "The remediation action creation module is unavailable."
        )

    elif not network_remediation_plan:
        demo_success(
            "No Azure NSG findings require remediation actions."
        )

    elif st.button(
        "Create Azure NSG Remediation Actions",
        key="create_azure_nsg_remediation_actions",
    ):
        try:
            created_actions = (
                create_actions_from_remediation_plan(
                    remediation_plan=network_remediation_plan,
                    client_name=selected_client_data[1],
                    cloud_provider="Azure",
                    azure_subscription_id=(
                        selected_client_data[6]
                    ),
                    azure_tenant_id=selected_client_data[7],
                    azure_client_id=selected_client_data[8],
                )
            )

            demo_success(
                f"Processed {len(created_actions)} Azure NSG "
                "remediation action(s). Review and approve them "
                "in the Execution Center."
            )

            demo_json(created_actions)

        except Exception as error:
            logger.exception(
                "Azure NSG remediation action creation failed."
            )
            st.error(
                f"Unable to create Azure NSG remediation "
                f"actions: {error}"
            )

    st.divider()

if azure_storage_exposure:
    st.header("Azure Storage Exposure Analysis")

    storage_client_name = st.session_state.get(
        "azure_storage_exposure_client",
        azure_display_client_name,
    )

    demo_caption(
        f"Latest storage security analysis for {storage_client_name}"
    )

    storage_summary = azure_storage_exposure.get(
        "summary",
        {},
    )

    (
        storage_col1,
        storage_col2,
        storage_col3,
        storage_col4,
        storage_col5,
    ) = st.columns(5)

    storage_col1.metric(
        "Storage Accounts",
        storage_summary.get("storage_accounts", 0),
    )
    storage_col2.metric(
        "Exposed Accounts",
        storage_summary.get("exposed_accounts", 0),
    )
    storage_col3.metric(
        "High Findings",
        storage_summary.get("high", 0),
    )
    storage_col4.metric(
        "Medium Findings",
        storage_summary.get("medium", 0),
    )
    storage_col5.metric(
        "Total Findings",
        storage_summary.get("findings", 0),
    )

    storage_accounts = azure_storage_exposure.get(
        "storage_accounts",
        [],
    )
    storage_findings = azure_storage_exposure.get(
        "findings",
        [],
    )

    high_storage_findings = [
        finding
        for finding in storage_findings
        if str(
            finding.get("severity", "")
        ).strip().lower() in {"critical", "high"}
    ]

    (
        storage_findings_tab,
        exposed_storage_tab,
        storage_configuration_tab,
    ) = st.tabs(
        [
            "All Findings",
            "High-Risk Findings",
            "Storage Configuration",
        ]
    )

    with storage_findings_tab:
        if storage_findings:
            storage_findings_df = pd.DataFrame(
                storage_findings
            )

            severity_order = {
                "Critical": 4,
                "High": 3,
                "Medium": 2,
                "Low": 1,
            }

            storage_findings_df[
                "Severity Rank"
            ] = storage_findings_df[
                "severity"
            ].map(severity_order).fillna(0)

            storage_findings_df = (
                storage_findings_df.sort_values(
                    by="Severity Rank",
                    ascending=False,
                ).drop(
                    columns=["Severity Rank"]
                )
            )

            demo_dataframe(
                storage_findings_df,
                width="stretch",
            )
        else:
            demo_success(
                "No Azure storage exposure findings were identified."
            )

    with exposed_storage_tab:
        if high_storage_findings:
            demo_dataframe(
                pd.DataFrame(high_storage_findings),
                width="stretch",
            )
        else:
            demo_success(
                "No critical or high-risk storage findings "
                "were identified."
            )

    with storage_configuration_tab:
        if storage_accounts:
            demo_dataframe(
                pd.DataFrame(storage_accounts),
                width="stretch",
            )
        else:
            demo_info(
                "No Azure storage accounts were discovered."
            )

    st.subheader("Azure Storage Remediation Actions")

    selected_provider = (
        str(selected_client_data[5] or "AWS").strip().upper()
        if selected_client_data is not None
        else ""
    )

    azure_action_creation_allowed = has_permission(
        st.session_state.get("user_role"),
        PERMISSION_EXECUTE_REMEDIATION,
    )

    valid_azure_binding = (
        selected_client_data is not None
        and selected_provider == "AZURE"
        and bool(selected_client_data[6])
        and bool(selected_client_data[7])
        and bool(selected_client_data[8])
    )

    unique_storage_targets = {}

    severity_rank = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    for finding in storage_findings:
        resource_id = str(
            finding.get("resource_id") or ""
        ).strip()

        if not resource_id:
            continue

        severity = str(
            finding.get("severity") or "Medium"
        ).strip()

        existing = unique_storage_targets.get(resource_id)

        if (
            existing is None
            or severity_rank.get(severity.lower(), 0)
            > severity_rank.get(
                str(existing.get("priority", "")).lower(),
                0,
            )
        ):
            unique_storage_targets[resource_id] = {
                "category": "Azure Storage",
                "finding": (
                    f"Azure Storage Risk - {resource_id}"
                ),
                "priority": severity.upper(),
            }

    remediation_plan = list(
        unique_storage_targets.values()
    )

    demo_caption(
        "Creates one approval-controlled remediation action per "
        "affected Azure Storage account. Duplicate open actions "
        "are reused."
    )

    if demo_mode_enabled():
        demo_info(
            "Action creation is disabled while the sanitized Azure "
            "demo dataset is active."
        )

    elif not azure_action_creation_allowed:
        demo_info(
            "Your role is not authorized to create executable "
            "remediation actions."
        )

    elif not valid_azure_binding:
        demo_info(
            "Select a saved Azure client with subscription, tenant, "
            "and client IDs before creating remediation actions."
        )

    elif create_actions_from_remediation_plan is None:
        demo_warning(
            "The remediation action creation module is unavailable."
        )

    elif not remediation_plan:
        demo_success(
            "No Azure Storage findings require remediation actions."
        )

    elif st.button(
        "Create Azure Storage Remediation Actions",
        key="create_azure_storage_remediation_actions",
    ):
        try:
            created_actions = (
                create_actions_from_remediation_plan(
                    remediation_plan=remediation_plan,
                    client_name=selected_client_data[1],
                    cloud_provider="Azure",
                    azure_subscription_id=(
                        selected_client_data[6]
                    ),
                    azure_tenant_id=selected_client_data[7],
                    azure_client_id=selected_client_data[8],
                )
            )

            demo_success(
                f"Processed {len(created_actions)} Azure Storage "
                "remediation action(s). Review and approve them "
                "in the Execution Center."
            )

            demo_json(created_actions)

        except Exception as error:
            logger.exception(
                "Azure Storage remediation action creation failed."
            )
            st.error(
                f"Unable to create Azure remediation actions: {error}"
            )

    st.divider()


azure_posture = st.session_state.get(
    "azure_security_posture"
)

if azure_posture:
    st.header("Microsoft Defender for Cloud")

    azure_posture_client = st.session_state.get(
        "azure_security_posture_client",
        "Selected Azure Client",
    )

    demo_caption(
        f"Latest Azure security posture for {azure_posture_client}"
    )

    posture_status = str(
        azure_posture.get(
            "discovery_status",
            "COMPLETE",
        )
    ).strip().upper()

    posture_errors = azure_posture.get(
        "errors",
        [],
    )

    if posture_status == "PARTIAL":
        demo_warning(
            "Defender discovery completed with partial failures. "
            "Available results are displayed below."
        )
    elif posture_status == "FAILED":
        st.error(
            "Defender discovery failed for all requested components."
        )
    else:
        demo_success(
            "Defender for Cloud discovery completed successfully."
        )

    if posture_errors:
        with st.expander(
            "Defender Discovery Errors",
            expanded=False,
        ):
            demo_dataframe(
                pd.DataFrame(posture_errors),
                width="stretch",
            )

    posture_summary = azure_posture.get(
        "summary",
        {},
    )

    metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = (
        st.columns(5)
    )

    metric_col1.metric(
        "Secure Scores",
        posture_summary.get("secure_scores", 0),
    )
    metric_col2.metric(
        "Assessments",
        posture_summary.get("assessments", 0),
    )
    metric_col3.metric(
        "Unhealthy",
        posture_summary.get("unhealthy", 0),
    )
    metric_col4.metric(
        "Critical Recommendations",
        posture_summary.get(
            "critical_assessments",
            0,
        ),
    )
    metric_col5.metric(
        "Security Alerts",
        posture_summary.get("alerts", 0),
    )

    detail_col1, detail_col2, detail_col3, detail_col4 = (
        st.columns(4)
    )

    detail_col1.metric(
        "Score Controls",
        posture_summary.get(
            "secure_score_controls",
            0,
        ),
    )
    detail_col2.metric(
        "Critical Alerts",
        posture_summary.get(
            "critical_alerts",
            0,
        ),
    )
    detail_col3.metric(
        "High Alerts",
        posture_summary.get(
            "high_alerts",
            0,
        ),
    )
    detail_col4.metric(
        "Standard Defender Plans",
        posture_summary.get(
            "standard_pricing_plans",
            0,
        ),
    )

    secure_scores = azure_posture.get(
        "secure_scores",
        [],
    )
    secure_score_controls = azure_posture.get(
        "secure_score_controls",
        [],
    )
    assessments = azure_posture.get(
        "assessments",
        [],
    )
    alerts = azure_posture.get(
        "alerts",
        [],
    )
    pricing_plans = azure_posture.get(
        "pricing_plans",
        [],
    )

    priority_assessments = [
        assessment
        for assessment in assessments
        if str(
            assessment.get(
                "priority",
                "",
            )
        ).upper()
        in {
            "CRITICAL",
            "HIGH",
        }
    ]

    (
        score_tab,
        controls_tab,
        priority_tab,
        assessments_tab,
        alerts_tab,
        plans_tab,
    ) = st.tabs(
        [
            "Secure Scores",
            "Score Controls",
            "Priority Assessments",
            "All Assessments",
            "Security Alerts",
            "Defender Plans",
        ]
    )

    with score_tab:
        if secure_scores:
            demo_dataframe(
                pd.DataFrame(secure_scores),
                width="stretch",
            )
        else:
            demo_info(
                "No Defender secure scores were returned."
            )

    with controls_tab:
        if secure_score_controls:
            demo_dataframe(
                pd.DataFrame(
                    secure_score_controls
                ),
                width="stretch",
            )
        else:
            demo_info(
                "No Defender secure-score controls were returned."
            )

    with priority_tab:
        if priority_assessments:
            demo_dataframe(
                pd.DataFrame(
                    priority_assessments
                ),
                width="stretch",
            )
        else:
            demo_success(
                "No critical or high Defender recommendations "
                "were returned."
            )

    with assessments_tab:
        if assessments:
            demo_dataframe(
                pd.DataFrame(assessments),
                width="stretch",
            )
        else:
            demo_info(
                "No Defender assessments were returned."
            )

    with alerts_tab:
        if alerts:
            demo_dataframe(
                pd.DataFrame(alerts),
                width="stretch",
            )
        else:
            demo_success(
                "No Defender security alerts were returned."
            )

    with plans_tab:
        if pricing_plans:
            demo_dataframe(
                pd.DataFrame(pricing_plans),
                width="stretch",
            )
        else:
            demo_info(
                "No Defender pricing plans were returned."
            )

    st.divider()

if selected_client_data:
    demo_success(
        f"Active Client: {selected_client_data[1]} ({selected_client_data[4]})"
    )
else:
    demo_info("Active Client: DGS Internal AWS Environment")
    

# ============================================================
# LOAD SAVED SECURITY FINDINGS
# ============================================================

rows = safe_get_findings()
df = normalize_findings(rows)

critical_count = len(df[df["Priority"] == "CRITICAL"]) if not df.empty else 0
high_count = len(df[df["Priority"] == "HIGH"]) if not df.empty else 0
kev_count = len(df[df["KEV Exploited"] == 1]) if not df.empty else 0
avg_risk = round(df["Risk Score"].mean(), 2) if not df.empty else 0
risk_rating = calculate_risk_rating(avg_risk)

azure_finding_summary = summarize_azure_findings(
    network_exposure=azure_network_exposure,
    storage_exposure=azure_storage_exposure,
)

multi_cloud_risk_score = round(
    calculate_unified_risk(
        base_risk=avg_risk,
        securityhub_count=0,
        guardduty_count=0,
        azure_critical_count=azure_finding_summary[
            "critical"
        ],
        azure_high_count=azure_finding_summary["high"],
        azure_medium_count=azure_finding_summary[
            "medium"
        ],
    ),
    2,
)

multi_cloud_risk_rating = calculate_risk_rating(
    multi_cloud_risk_score
)

summary = {
    "Critical Findings": critical_count,
    "High Findings": high_count,
    "KEV Exploited Findings": kev_count,
    "Average Risk Score": avg_risk,
    "Risk Rating": risk_rating,
    "Azure Critical Findings": azure_finding_summary[
        "critical"
    ],
    "Azure High Findings": azure_finding_summary["high"],
    "Azure Medium Findings": azure_finding_summary[
        "medium"
    ],
    "Azure Total Findings": azure_finding_summary["total"],
    "Multi-Cloud Risk Score": multi_cloud_risk_score,
    "Multi-Cloud Risk Rating": multi_cloud_risk_rating,
}

remediation_playbook = generate_remediation_playbook(df)
risk_narrative = generate_risk_narrative(summary)
ai_analysis = generate_ai_analysis(summary, remediation_playbook)
# ============================================================
# MANUAL AUTONOMOUS SCAN
# ============================================================

st.subheader("Manual Autonomous Scan")

can_run_scans = has_permission(
    st.session_state.get("user_role"),
    PERMISSION_RUN_SCANS,
)

if not can_run_scans:
    demo_info(
        "Your role has read-only access and cannot run security scans."
    )

if "last_scan_status" not in st.session_state:
    st.session_state["last_scan_status"] = "Idle"

if "last_scan_time" not in st.session_state:
    st.session_state["last_scan_time"] = "Never"

if st.button(
    "Run DGS Sentinel Scan Now",
    type="primary",
    key="run_dgs_sentinel_scan_now",
    disabled=not can_run_scans,
):

    if not can_run_scans:
        st.error(
            "Your role is not authorized to run security scans."
        )
        st.stop()

    if selected_client_data:
        demo_info(
            f"Preparing scan for client: {selected_client_data[1]} "
            f"({selected_client_data[4]})"
        )
    else:
        demo_info("Preparing scan for DGS Internal AWS Environment")

    st.session_state["last_scan_status"] = "Running"

    with st.spinner("Running autonomous scan..."):
        try:
            selected_cloud_provider = (
                normalize_cloud_provider(
                    selected_client_data[5]
                    if selected_client_data
                    else "AWS"
                )
            )

            results = {}
            azure_scan_discovery = None

            if (
                selected_client_data
                and selected_cloud_provider == "AZURE"
            ):
                azure_scan_discovery = azure_discovery

                discovery_client_name = st.session_state.get(
                    "azure_resource_discovery_client"
                )

                if (
                    not demo_mode_enabled()
                    and discovery_client_name
                    and discovery_client_name
                    != selected_client_data[1]
                ):
                    raise RuntimeError(
                        "The current Azure discovery results belong "
                        f"to {discovery_client_name}, not "
                        f"{selected_client_data[1]}. Run Azure "
                        "Resource Discovery again."
                    )

                if not azure_scan_discovery:
                    raise RuntimeError(
                        "Run Azure Resource Discovery before "
                        "starting the DGS Sentinel Azure scan."
                    )

                azure_resource_counts = (
                    summarize_azure_resources(
                        azure_scan_discovery
                    )
                )

                demo_success(
                    "Azure posture scan completed using the "
                    "latest Azure discovery results. "
                    f"Virtual machines: "
                    f"{azure_resource_counts['virtual_machines']}. "
                    f"Storage accounts: "
                    f"{azure_resource_counts['storage_accounts']}. "
                    f"Network security groups: "
                    f"{azure_resource_counts['network_security_groups']}. "
                    f"Public IP addresses: "
                    f"{azure_resource_counts['public_ip_addresses']}."
                )

            elif selected_client_data:
                if run_client_scan is None:
                    raise RuntimeError(
                        "AWS client scan engine is not available."
                    )

                role_arn = selected_client_data[3]

                if get_client_key is None:
                    raise RuntimeError(
                        "Client tenant-key lookup is unavailable."
                    )

                client_key = get_client_key(
                    selected_client_data[0]
                )

                if not client_key:
                    raise RuntimeError(
                        "The selected client does not have a "
                        "tenant key."
                    )

                results = run_client_scan(
                    role_arn,
                    client_name=selected_client_data[1],
                    client_key=client_key,
                )

                if results.get("identity", {}).get("status") != "SUCCESS":
                    raise RuntimeError(
                        f"Unable to assume role for client: {selected_client_data[1]}"
                    )

                demo_success(
                    f"Phase 13 client scan completed. "
                    f"Regions scanned: {len(results.get('regions_scanned', []))}. "
                    f"EC2 assets: {results.get('ec2_count', 0)}. "
                    f"IAM users: {results.get('iam_count', 0)}. "
                    f"S3 buckets: {results.get('s3_count', 0)}. "
                    f"Security Hub findings: "
                    f"{results.get('securityhub_count', 0)}. "
                    f"GuardDuty findings: "
                    f"{results.get('guardduty_count', 0)}. "
                    f"AWS Config rules: "
                    f"{results.get('config_rule_count', 0)}. "
                    f"Noncompliant Config rules: "
                    f"{results.get('config_noncompliant_rule_count', 0)}. "
                    f"Remediation findings: "
                    f"{results.get('remediation_count', 0)}."
                )

                if results.get("ec2_instances"):
                    st.subheader("Discovered EC2 Instances")
                    demo_dataframe(
                        results.get("ec2_instances"),
                        width="stretch"
                    )

                if results.get("iam_users"):
                    st.subheader("Discovered IAM Users")
                    demo_dataframe(
                        results.get("iam_users"),
                        width="stretch"
                    )

                if results.get("s3_buckets"):
                    st.subheader("Discovered S3 Buckets")
                    demo_dataframe(
                        results.get("s3_buckets"),
                        width="stretch"
                    )

                if results.get("securityhub_findings"):
                    st.subheader("Security Hub Findings")
                    demo_dataframe(
                        results.get("securityhub_findings"),
                        width="stretch"
                    )

                if results.get("guardduty_findings"):
                    st.subheader("GuardDuty Findings")
                    demo_dataframe(
                        results.get("guardduty_findings"),
                        width="stretch"
                    )

                if results.get("config_findings"):
                    st.subheader(
                        "AWS Config Noncompliance"
                    )
                    demo_dataframe(
                        results.get("config_findings"),
                        width="stretch"
                    )

                if results.get("scan_errors"):
                    demo_warning(
                        "Some read-only checks could not be completed."
                    )

                    demo_dataframe(
                        [
                            {"Warning": warning}
                            for warning in results.get("scan_errors", [])
                        ],
                        width="stretch"
                    )
            else:
                if run_scan is None:
                    raise RuntimeError(
                        "scan_engine.run_scan is not available."
                    )

                run_scan()

            snapshot_assets = []

            try:
                from asset_db import get_all_assets_admin

                raw_assets = get_all_assets_admin()

                for asset in raw_assets:
                    snapshot_assets.append({
                        "asset_id": asset[0],
                        "asset_type": asset[1],
                        "account_id": asset[2],
                        "region": asset[3],
                        "hostname": asset[4],
                        "private_ip": asset[5],
                        "public_ip": asset[6],
                        "state": asset[7],
                        "risk_score": asset[8],
                        "last_scan": asset[9]
                    })

                if (
                    selected_client_data
                    and selected_cloud_provider == "AZURE"
                ):
                    snapshot_assets = (
                        build_azure_snapshot_assets(
                            azure_scan_discovery,
                            subscription_id=(
                                selected_client_data[6]
                            ),
                        )
                    )

                    azure_resource_counts = (
                        summarize_azure_resources(
                            azure_scan_discovery
                        )
                    )
                else:
                    azure_resource_counts = (
                        summarize_azure_resources(None)
                    )

                snapshot_summary = {
                    "security_score": max(0, 100 - int(avg_risk)),
                    "risk_rating": risk_rating,
                    "multi_cloud_security_score": round(
                        max(
                            0,
                            100 - float(multi_cloud_risk_score),
                        ),
                        2,
                    ),
                    "multi_cloud_risk_score": (
                        multi_cloud_risk_score
                    ),
                    "multi_cloud_risk_rating": (
                        multi_cloud_risk_rating
                    ),
                    "azure_critical_findings": (
                        azure_finding_summary["critical"]
                    ),
                    "azure_high_findings": (
                        azure_finding_summary["high"]
                    ),
                    "azure_medium_findings": (
                        azure_finding_summary["medium"]
                    ),
                    "azure_total_findings": (
                        azure_finding_summary["total"]
                    ),
                    "azure_virtual_machines": (
                        azure_resource_counts[
                            "virtual_machines"
                        ]
                    ),
                    "azure_storage_accounts": (
                        azure_resource_counts[
                            "storage_accounts"
                        ]
                    ),
                    "azure_network_security_groups": (
                        azure_resource_counts[
                            "network_security_groups"
                        ]
                    ),
                    "azure_public_ip_addresses": (
                        azure_resource_counts[
                            "public_ip_addresses"
                        ]
                    ),
                    "azure_network_interfaces": (
                        azure_resource_counts[
                            "network_interfaces"
                        ]
                    ),
                    "cloud_provider": selected_cloud_provider,
                    "assets": len(snapshot_assets),
                    "accounts_scanned": 1,
                    "ec2_assets": len([
                        asset
                        for asset in snapshot_assets
                        if asset.get("asset_type") == "EC2"
                    ]),
                    "iam_users": len([
                        asset
                        for asset in snapshot_assets
                        if asset.get("asset_type") == "IAM User"
                    ]),
                    "s3_buckets": len([
                        asset
                        for asset in snapshot_assets
                        if asset.get("asset_type") == "S3 Bucket"
                    ]),
                    "securityhub_findings": (
                        results.get(
                            "securityhub_count",
                            0
                        )
                        if selected_client_data
                        else high_count + critical_count
                    ),
                    "guardduty_findings": (
                        results.get(
                            "guardduty_count",
                            0
                        )
                        if selected_client_data
                        else 0
                    ),
                    "kev_cves": kev_count,
                    "remediation_actions": len(remediation_playbook),
                    "critical_vulnerabilities": critical_count
                }

                snapshot_path = save_scan_snapshot(
                    summary=snapshot_summary,
                    assets=snapshot_assets,
                    remediation=remediation_playbook
                )

                demo_success(
                    f"Snapshot saved: {snapshot_path.get('file_path')} "
                    f"(old snapshots deleted: {snapshot_path.get('deleted_old_snapshots', 0)})"
                )

            except Exception as snapshot_error:
                demo_warning(f"Snapshot save skipped: {snapshot_error}")

            st.session_state["last_scan_status"] = "Completed"
            st.session_state["last_scan_time"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if selected_client_data:
                demo_success(
                    f"Scan completed for client: {selected_client_data[1]}"
                )
            else:
                demo_success(
                    "Scan completed for DGS Internal AWS Environment"
                )

        except Exception as e:
            st.session_state["last_scan_status"] = "Failed"
            st.error(f"Scan failed: {e}")

demo_info(
    f"""
Scan Status: {st.session_state['last_scan_status']}

Last Scan Time: {st.session_state['last_scan_time']}
"""
)

st.subheader("Scheduled Scan Readiness")

scan_cadence = st.selectbox(
    "Suggested scan cadence",
    [
        "Every 4 hours",
        "Every 8 hours",
        "Every 12 hours",
        "Every 24 hours"
    ],
    index=3
)

readiness_col1, readiness_col2, readiness_col3 = st.columns(3)

readiness_col1.metric(
    "Automation Status",
    "Manual Ready"
)

readiness_col2.metric(
    "Selected Cadence",
    scan_cadence
)

readiness_col3.metric(
    "Next Step",
    "Scheduler Hook"
)

demo_caption(
    "Scheduled scanning readiness is prepared for future cron, GitHub Actions, or cloud scheduler integration."
)

# ===========================================================
# EXECUTIVE SECURITY OVERVIEW
# ============================================================

st.header("Executive Security Overview")

(
    metric_col1,
    metric_col2,
    metric_col3,
    metric_col4,
    metric_col5,
) = st.columns(5)

metric_col1.metric(
    "AWS Critical Findings",
    critical_count,
)
metric_col2.metric(
    "Azure Findings",
    azure_finding_summary["total"],
)
metric_col3.metric(
    "AWS Baseline Risk",
    avg_risk,
)
metric_col4.metric(
    "Multi-Cloud Risk",
    multi_cloud_risk_score,
)
metric_col5.metric(
    "Risk Rating",
    multi_cloud_risk_rating,
)

demo_caption(
    "Azure severity contribution: "
    f"{azure_finding_summary['critical']} critical, "
    f"{azure_finding_summary['high']} high, and "
    f"{azure_finding_summary['medium']} medium findings."
)

gauge_fig = go.Figure(
    go.Indicator(
        mode="gauge+number",
        value=multi_cloud_risk_score,
        title={"text": "Enterprise Multi-Cloud Risk Gauge"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "darkblue"},
            "steps": [
                {"range": [0, 25], "color": "lightgreen"},
                {"range": [25, 50], "color": "yellow"},
                {"range": [50, 75], "color": "orange"},
                {"range": [75, 100], "color": "red"},
            ],
        },
    )
)

st.plotly_chart(gauge_fig, width="stretch")


# ============================================================
# AWS ACCOUNT VISIBILITY
# ============================================================

st.subheader("AWS Account Visibility")

identity = get_basic_aws_identity()

aws_col1, aws_col2 = st.columns(2)
aws_col1.metric("AWS Account", identity.get("Account", "Unavailable"))
aws_col2.metric("AWS User/Role", identity.get("UserId", "Unavailable"))

demo_caption(identity.get("Arn", ""))

if enable_org_discovery:
    st.subheader("AWS Organization Accounts")

    organization_accounts = get_organization_data()

    if organization_accounts:
        org_df = pd.DataFrame(organization_accounts)
        demo_dataframe(org_df, width="stretch")

        active_accounts = len(org_df[org_df["Status"] == "ACTIVE"])
        suspended_accounts = len(org_df[org_df["Status"] != "ACTIVE"])

        org_col1, org_col2, org_col3 = st.columns(3)
        org_col1.metric("Organization Accounts", len(org_df))
        org_col2.metric("Active Accounts", active_accounts)
        org_col3.metric("Suspended Accounts", suspended_accounts)
    else:
        demo_info(
            "No AWS Organization accounts available or Organizations is not enabled."
        )


# ============================================================
# AWS GUARDDUTY THREAT INTELLIGENCE
# ============================================================

st.subheader("AWS GuardDuty Threat Intelligence")

guardduty_findings = get_guardduty_data()

if guardduty_findings:
    gd_df = pd.DataFrame(guardduty_findings)
    demo_dataframe(gd_df, width="stretch")

    if "Severity" in gd_df.columns:
        gd_df["Severity"] = pd.to_numeric(gd_df["Severity"], errors="coerce").fillna(0)
        high_gd = len(gd_df[gd_df["Severity"] >= 7])
        medium_gd = len(
            gd_df[
                (gd_df["Severity"] >= 4)
                & (gd_df["Severity"] < 7)
            ]
        )

        gd_col1, gd_col2 = st.columns(2)
        gd_col1.metric("High Severity Threats", high_gd)
        gd_col2.metric("Medium Severity Threats", medium_gd)
else:
    demo_info("No GuardDuty findings available or GuardDuty is not enabled.")


# ============================================================
# SAVED THREAT FINDINGS
# ============================================================

st.subheader("Saved Threat Findings")

if not df.empty:
    demo_dataframe(
        df.style.apply(highlight_priority, axis=1),
        width="stretch"
    )

    top_threats = df.sort_values("Risk Score", ascending=False).head(10)

    if not top_threats.empty:
        st.subheader("Top Threats by Risk Score")
        bar_fig = px.bar(
            top_threats,
            x="CVE ID",
            y="Risk Score",
            color="Priority",
            title="Top Threats by Risk Score"
        )
        st.plotly_chart(bar_fig, width="stretch")

    st.subheader("Threat Severity Distribution")
    severity_counts = df["Priority"].value_counts().reset_index()
    severity_counts.columns = ["Priority", "Count"]

    pie_fig = px.pie(
        severity_counts,
        values="Count",
        names="Priority",
        title="Threat Severity Distribution"
    )
    st.plotly_chart(pie_fig, width="stretch")

    st.subheader("Risk Trend Analytics")
    trend_df = (
        df.groupby("Scan Time")["Risk Score"]
        .mean()
        .reset_index()
        .sort_values("Scan Time")
    )

    if not trend_df.empty:
        line_fig = px.line(
            trend_df,
            x="Scan Time",
            y="Risk Score",
            title="Average Risk Score Over Time"
        )
        st.plotly_chart(line_fig, width="stretch")
else:
    demo_warning("No saved findings yet. Run the autonomous scanner first.")
    st.code("python headless_scan.py", language="bash")


# ============================================================
# REMEDIATION PRIORITY MATRIX
# ============================================================

st.subheader("Remediation Priority Matrix")

if remediation_playbook:
    remediation_df = pd.DataFrame(remediation_playbook)
    demo_dataframe(remediation_df, width="stretch")
else:
    demo_info("No remediation priorities available yet.")


# ============================================================
# AI EXECUTIVE RISK SUMMARY
# ============================================================

st.subheader("AI Executive Risk Summary")

demo_markdown(risk_narrative)

with st.expander("AI Executive Analysis", expanded=True):
    demo_markdown(ai_analysis)


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

st.subheader("MITRE ATT&CK Mapping")

mitre_df = build_mitre_mapping(df)

if not mitre_df.empty:
    demo_dataframe(mitre_df, width="stretch")
else:
    demo_info("No MITRE mappings available yet.")


# ============================================================
# EXECUTIVE EXPORTS
# ============================================================

st.subheader("Executive Exports")

export_col1, export_col2, export_col3 = st.columns(3)

csv_data = df.to_csv(index=False).encode("utf-8") if not df.empty else b""
mitre_csv = mitre_df.to_csv(index=False).encode("utf-8") if not mitre_df.empty else b""
asset_summary = {}

try:
    from client_db import get_clients
    from asset_db import get_all_assets_admin

    pdf_clients = get_clients()
    pdf_assets = get_all_assets_admin()

    if pdf_assets:
        pdf_asset_df = pd.DataFrame(
            pdf_assets,
            columns=[
                "Asset ID",
                "Asset Type",
                "Account ID",
                "Region",
                "Hostname",
                "Private IP",
                "Public IP",
                "State",
                "Risk Score",
                "Last Scan"
            ]
        )

        asset_summary = {
            "Total Clients": len(pdf_clients),
            "Total Assets": len(pdf_asset_df),
            "Average Asset Risk": round(pdf_asset_df["Risk Score"].mean(), 2),
            "Critical Assets": len(pdf_asset_df[pdf_asset_df["Risk Score"] >= 80]),
            "Public Assets": len(pdf_asset_df[pdf_asset_df["Public IP"].notna() & (pdf_asset_df["Public IP"] != "")]),
            "Stopped Assets": len(pdf_asset_df[pdf_asset_df["State"] == "stopped"])
        }
    else:
        asset_summary = {
            "Total Clients": len(pdf_clients),
            "Total Assets": 0,
            "Average Asset Risk": 0,
            "Critical Assets": 0,
            "Public Assets": 0,
            "Stopped Assets": 0
        }

except Exception:
    asset_summary = {}

pdf_buffer = generate_pdf(
    ai_analysis=ai_analysis,
    summary=summary,
    remediation_playbook=remediation_playbook,
    risk_narrative=risk_narrative,
    asset_summary=asset_summary
)

export_col1.download_button(
    label="Download Findings CSV",
    data=csv_data,
    file_name="dgs_sentinel_findings.csv",
    mime="text/csv",
    disabled=df.empty
)

export_col2.download_button(
    label="Download MITRE Mapping CSV",
    data=mitre_csv,
    file_name="dgs_sentinel_mitre_mapping.csv",
    mime="text/csv",
    disabled=mitre_df.empty
)

export_col3.download_button(
    label="Download Executive PDF Report",
    data=pdf_buffer,
    file_name="dgs_sentinel_executive_report.pdf",
    mime="application/pdf"
)
