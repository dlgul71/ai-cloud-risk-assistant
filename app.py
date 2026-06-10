from datetime import datetime, timedelta
from io import BytesIO
import hmac

import boto3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from risk_engine import calculate_unified_risk
from scan_engine_phase3_assumerole import run_client_scan
from snapshot_engine import save_scan_snapshot
from kev_lookup import check_cve_in_kev, fetch_cisa_kev


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
    from client_db import init_client_db, add_client, get_clients
except Exception:
    init_client_db = None
    add_client = None
    get_clients = None

try:
    from streamlit_autorefresh import st_autorefresh
    AUTOREFRESH_AVAILABLE = True
except Exception:
    AUTOREFRESH_AVAILABLE = False


# ============================================================
# PAGE CONFIGURATION
# ============================================================

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

    session_timeout_minutes = 30

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
            st.warning("Session expired. Please login again.")
            st.rerun()

    if st.session_state["authenticated"]:
        return True

    st.title("🛡️ DGS Sentinel AI Login")
    st.caption("Protected Cloud Security Analytics Platform")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login", type="primary"):
        try:
            correct_username = st.secrets["auth"]["username"]
            correct_password = st.secrets["auth"]["password"]
        except Exception:
            st.error("Authentication is not configured. Check .streamlit/secrets.toml.")
            return False

        if (
            hmac.compare_digest(username, correct_username)
            and hmac.compare_digest(password, correct_password)
        ):
            st.session_state["authenticated"] = True
            st.session_state["login_time"] = datetime.now()
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
        st.warning(f"Client database could not be initialized: {e}")


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
        st.warning(f"Unable to load saved findings: {e}")
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
        st.warning(f"CISA KEV enrichment unavailable: {e}")

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
    """Generate an executive narrative from summary metrics."""
    risk_rating = summary.get("Risk Rating", "UNKNOWN")
    critical = summary.get("Critical Findings", 0)
    kev = summary.get("KEV Exploited Findings", 0)

    return f"""
DGS Sentinel AI assessed cloud security posture and identified an overall rating of {risk_rating}.
The environment currently shows {critical} critical findings and {kev} known exploited vulnerability indicators.

Security leadership should prioritize remediation of exploited vulnerabilities, review internet-facing assets,
validate identity controls, and confirm that remediation actions are tracked to completion.
"""


def generate_ai_analysis(summary, remediation_playbook):
    """Generate a deterministic executive AI-style summary without requiring API access."""
    top_actions = remediation_playbook[:3]

    lines = [
        "Executive Analysis:",
        "",
        f"The current cloud security risk posture is classified as {summary.get('Risk Rating', 'UNKNOWN')}.",
        "Priority should be given to findings that combine high exploitability, known exploitation intelligence, and public exposure.",
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


def get_guardduty_data():
    """Safely load GuardDuty findings."""
    if get_guardduty_findings is None:
        return []

    try:
        return get_guardduty_findings()
    except Exception as e:
        st.warning(f"GuardDuty data unavailable: {e}")
        return []


def get_organization_data():
    """Safely load AWS Organizations accounts."""
    if get_organization_accounts is None:
        return []

    try:
        return get_organization_accounts()
    except Exception:
        st.info("AWS Organizations is not enabled or this account is not part of an organization.")
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

with st.sidebar:

    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.session_state["login_time"] = None
        st.rerun()

    page = st.radio(
        "Navigation",
        [
            "Dashboard",
            "Executive Dashboard",
            "SOC Dashboard",
            "Risk Trends",
            "Remediation Center",
            "Execution Center",
            "Client Accounts",
            "Asset Dashboard"
        ],
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

    from asset_db import get_assets
    from remediation_db import get_remediation_items
    import pandas as pd

    st.title("SOC Dashboard")
    st.caption("Executive security operations overview")

    assets = get_assets()
    remediation_items = get_remediation_items()

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
                "Risk Score"
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

        st.dataframe(
            top_soc_assets,
            width="stretch"
        )

    if remediation_items:
        st.subheader("Top Remediation Items")

        top_soc_remediation = soc_remediation_df.sort_values(
            by="Risk Score",
            ascending=False
        ).head(10)

        st.dataframe(
            top_soc_remediation,
            width="stretch"
        )



if page == "Risk Trends":

    import json
    from pathlib import Path
    import pandas as pd

    st.title("Risk Trends")
    st.caption("Historical risk trend analysis from saved scan snapshots")

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
                    "Security Score": summary_data.get("security_score", 0),
                    "Risk Rating": summary_data.get("risk_rating", "UNKNOWN"),
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
                st.warning(f"Unable to load snapshot {snapshot_file.name}: {e}")

    if trend_rows:
        trend_df = pd.DataFrame(trend_rows)
        trend_df["Scan Time"] = pd.to_datetime(trend_df["Scan Time"], errors="coerce")
        trend_df = trend_df.dropna(subset=["Scan Time"]).sort_values("Scan Time")

        latest = trend_df.iloc[-1]

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Latest Security Score", latest["Security Score"])
        col2.metric("Latest Risk Rating", latest["Risk Rating"])
        col3.metric("Latest Assets", latest["Assets"])
        col4.metric("Latest Remediation Actions", latest["Remediation Actions"])

        if len(trend_df) >= 2:
            previous = trend_df.iloc[-2]

            score_delta = latest["Security Score"] - previous["Security Score"]
            securityhub_delta = latest["Security Hub Findings"] - previous["Security Hub Findings"]
            guardduty_delta = latest["GuardDuty Findings"] - previous["GuardDuty Findings"]
            remediation_delta = latest["Remediation Actions"] - previous["Remediation Actions"]

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
                remediation_delta
            )

        st.subheader("Security Score Over Time")
        st.line_chart(
            trend_df.set_index("Scan Time")["Security Score"]
        )

        st.subheader("Findings Trend")

        findings_trend = trend_df.set_index("Scan Time")[
            [
                "Security Hub Findings",
                "GuardDuty Findings",
                "KEV CVEs",
                "Critical Vulnerabilities"
            ]
        ]

        st.line_chart(findings_trend)

        st.subheader("Historical Snapshot Table")
        st.dataframe(
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
                st.download_button(
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
                    latest_summary.get("guardduty_findings", 0) - previous_summary.get("guardduty_findings", 0)
                )

                st.caption(
                    f"Comparing latest snapshot {latest_file.name} against previous snapshot {previous_file.name}."
                )
            else:
                st.info("At least two snapshots are required for comparison.")

    else:
        st.info("No scan snapshots found yet. Run scans to build historical trend data.")


if page == "Executive Dashboard":

    from client_db import get_clients
    from asset_db import get_assets
    import pandas as pd

    st.title("Executive Dashboard")
    st.caption("Multi-client executive risk overview")

    clients = get_clients()
    assets = get_assets()

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

        st.dataframe(
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

        st.dataframe(
            client_risk_df,
            width="stretch"
        )



if page == "Asset Dashboard":

    from asset_db import get_assets
    import pandas as pd

    st.title("Asset Dashboard")
    st.caption("CAASM-style asset inventory for client AWS assets")

    assets = get_assets()

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

        st.dataframe(
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

        st.markdown(f"### {selected_asset['Asset ID']}")

        detail_col1, detail_col2, detail_col3 = st.columns(3)

        detail_col1.metric("Asset Type", selected_asset["Asset Type"])
        detail_col2.metric("Region", selected_asset["Region"])
        detail_col3.metric("Risk Score", selected_asset["Risk Score"])

        st.write("**Account ID:**", selected_asset["Account ID"])
        st.write("**Private IP:**", selected_asset["Private IP"])
        st.write("**Public IP:**", selected_asset["Public IP"] or "None")
        st.write("**State:**", selected_asset["State"])
        st.write("**Last Scan:**", selected_asset["Last Scan"])

        if selected_asset["Public IP"]:
            st.error(
                "Exposure Finding: This asset has a public IP address. Review security groups, inbound ports, and business justification."
            )
        else:
            st.success(
                "Exposure Finding: No public IP detected for this asset."
            )

        if selected_asset["Risk Score"] >= 80:
            st.error("Remediation Priority: Critical — immediate review required.")
        elif selected_asset["Risk Score"] >= 50:
            st.warning("Remediation Priority: High — remediate within SLA.")
        else:
            st.info("Remediation Priority: Standard monitoring.")

    else:
        st.info("No assets found yet. Run a Phase 3 client scan first.")



if page == "Remediation Center":

    from remediation_db import get_remediation_items, update_remediation_status
    import pandas as pd

    st.title("Remediation Center")
    st.caption("Autonomous remediation recommendations generated from AWS findings")

    remediation_items = get_remediation_items()

    columns = [
        "ID",
        "Created At",
        "Category",
        "Priority",
        "Finding",
        "Recommendation",
        "Owner",
        "Status",
        "Risk Score"
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
        col5.metric("Oldest Item Days", oldest_item)

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

        kpi_col1.metric("In Progress", in_progress_items)
        kpi_col2.metric("Resolved", resolved_items)
        kpi_col3.metric("Accepted Risk", accepted_risk_items)
        kpi_col4.metric("Resolution Rate", f"{resolution_rate}%")

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
            st.write("Items by Priority")
            st.bar_chart(remediation_df["Priority"].value_counts())

        with chart_col2:
            st.write("Items by Status")
            st.bar_chart(remediation_df["Status"].value_counts())

        with chart_col3:
            st.write("Items by Category")
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

        st.dataframe(
            remediation_df,
            width="stretch"
        )

        remediation_csv = remediation_df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download Filtered Remediation CSV",
            data=remediation_csv,
            file_name="dgs_sentinel_remediation_queue.csv",
            mime="text/csv"
        )

        st.subheader("Top Recommendation")

        top_item = remediation_df.iloc[0]

        st.markdown(f"### {top_item['Finding']}")
        st.write("**Priority:**", top_item["Priority"])
        st.write("**Category:**", top_item["Category"])
        st.write("**Owner:**", top_item["Owner"])
        st.write("**Recommendation:**", top_item["Recommendation"])

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
            ]
        )

        if st.button("Update Remediation Status"):
            update_remediation_status(
                int(selected_item_id),
                new_status
            )

            st.success(
                f"Remediation item {selected_item_id} updated to {new_status}."
            )

            st.rerun()

    else:
        st.info("No remediation items found yet. Run a scan to generate recommendations.")




if page == "Execution Center":

    from remediation_execution import (
        get_execution_actions,
        update_execution_action,
        simulate_execution
    )
    from remediation_audit import get_remediation_audit
    import pandas as pd

    st.title("Execution Center")
    st.caption("Autonomous remediation execution queue")

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
        "Notes"
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

        col1, col2, col3 = st.columns(3)

        col1.metric("Pending Approval", pending_approval)
        col2.metric("Approved", approved_actions)
        col3.metric("Completed", completed_actions)

        st.subheader("Execution Queue")

        st.dataframe(
            actions_df,
            width="stretch"
        )

        st.subheader("Execution Approval Workflow")

        selected_action_id = st.selectbox(
            "Select action ID",
            actions_df["ID"].tolist()
        )

        approval_status = st.selectbox(
            "Approval status",
            [
                "Pending Approval",
                "Approved",
                "Rejected"
            ]
        )

        execution_status = st.selectbox(
            "Execution status",
            [
                "Not Started",
                "Ready",
                "Executing",
                "Completed",
                "Failed"
            ]
        )

        if st.button("Update Execution Action"):
            update_execution_action(
                int(selected_action_id),
                approval_status=approval_status,
                execution_status=execution_status
            )

            st.success(
                f"Execution action {selected_action_id} updated."
            )

            st.rerun()

        st.subheader("Run Approved Simulation")

        st.caption(
            "Simulation mode does not modify AWS resources. "
            "It validates the remediation workflow and creates an audit record."
        )

        if st.button("Run Approved Simulation"):
            try:
                simulation_result = simulate_execution(
                    int(selected_action_id)
                )

                st.success(
                    f"Simulation completed for action "
                    f"{simulation_result.get('action_id')}."
                )

                st.json(simulation_result)

                st.rerun()

            except Exception as e:
                st.error(f"Simulation failed: {e}")

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

            st.dataframe(
                audit_df,
                width="stretch"
            )

            audit_csv = audit_df.to_csv(index=False).encode("utf-8")

            st.download_button(
                label="Download Audit Trail CSV",
                data=audit_csv,
                file_name="dgs_sentinel_execution_audit.csv",
                mime="text/csv"
            )

        else:
            st.info("No execution audit events found yet.")

    else:
        st.info("No remediation actions have been generated yet.")



if page == "Client Accounts":

    st.title("🛡️ DGS Sentinel AI")
    st.caption("Client Account Management")

    st.header("Client Account Management")

    st.markdown(
        "Add AWS client accounts using read-only IAM AssumeRole access."
    )

    if add_client is None or get_clients is None:
        st.error(
            "Client database module is unavailable. Confirm client_db.py exists and imports correctly."
        )
        st.stop()

    with st.form("client_account_form"):
        client_name = st.text_input("Client Name")
        aws_account_id = st.text_input("AWS Account ID")
        role_arn = st.text_input("AWS Role ARN")

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
            if client_name and aws_account_id and role_arn:
                add_client(
                    client_name,
                    aws_account_id,
                    role_arn,
                    environment
                )
                st.success("Client account added successfully.")
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
                "Environment"
            ]
        )

        st.dataframe(
            clients_df,
            width="stretch"
        )
    else:
        st.info("No client accounts saved yet.")

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
            f"{client[1]} | {client[2]} | {client[4]}"
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
# TEST CLIENT AWS CONNECTION
# ============================================================

if selected_client_data is not None:

    if st.sidebar.button(
        "Test Client AWS Connection",
        key="test_client_connection"
    ):

        role_arn = selected_client_data[3]

        session = assume_client_role(role_arn)

        if session:
            try:
                sts = session.client("sts")
                identity = sts.get_caller_identity()

                st.sidebar.success(
                    f"Connected to AWS Account: {identity['Account']}"
                )

            except Exception as e:
                st.sidebar.error(
                    f"Connection test failed: {e}"
                )
else:
    st.sidebar.info(
    "Select a saved client from Active Client Account to enable AWS connection test."
)
    
# ============================================================
# MAIN DASHBOARD HEADER
# ============================================================

if page != "Dashboard":
    st.stop()

st.title("🛡️ DGS Sentinel AI")
st.caption("AI-Powered CAASM / CSPM / CNAPP / SIEM Platform")

if selected_client_data:
    st.success(
        f"Active Client: {selected_client_data[1]} ({selected_client_data[4]})"
    )
else:
    st.info("Active Client: DGS Internal AWS Environment")
    

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

summary = {
    "Critical Findings": critical_count,
    "High Findings": high_count,
    "KEV Exploited Findings": kev_count,
    "Average Risk Score": avg_risk,
    "Risk Rating": risk_rating
}

remediation_playbook = generate_remediation_playbook(df)
risk_narrative = generate_risk_narrative(summary)
ai_analysis = generate_ai_analysis(summary, remediation_playbook)
# ============================================================
# MANUAL AUTONOMOUS SCAN
# ============================================================

st.subheader("Manual Autonomous Scan")

if "last_scan_status" not in st.session_state:
    st.session_state["last_scan_status"] = "Idle"

if "last_scan_time" not in st.session_state:
    st.session_state["last_scan_time"] = "Never"

if st.button(
    "Run DGS Sentinel Scan Now",
    type="primary",
    key="run_dgs_sentinel_scan_now"
):

    if selected_client_data:
        st.info(
            f"Preparing scan for client: {selected_client_data[1]} "
            f"({selected_client_data[4]})"
        )
    else:
        st.info("Preparing scan for DGS Internal AWS Environment")

    st.session_state["last_scan_status"] = "Running"

    with st.spinner("Running autonomous scan..."):
        try:
            if run_scan is None:
                raise RuntimeError("scan_engine.run_scan is not available.")

            if selected_client_data:
                role_arn = selected_client_data[3]

                results = run_client_scan(role_arn)

                if results.get("identity", {}).get("status") != "SUCCESS":
                    raise RuntimeError(
                        f"Unable to assume role for client: {selected_client_data[1]}"
                    )

                st.success(
                    f"Phase 3 multi-region scan completed. "
                    f"Regions scanned: {len(results.get('regions_scanned', []))}. "
                    f"EC2 assets found: {results.get('ec2_count', 0)}."
                )

                if results.get("ec2_instances"):
                    st.dataframe(results.get("ec2_instances"), width='stretch')
            else:
                run_scan()

            snapshot_assets = []

            try:
                from asset_db import get_assets

                raw_assets = get_assets()

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

                snapshot_summary = {
                    "security_score": max(0, 100 - int(avg_risk)),
                    "risk_rating": risk_rating,
                    "assets": len(snapshot_assets),
                    "accounts_scanned": 1,
                    "ec2_assets": len([a for a in snapshot_assets if a.get("asset_type") == "EC2"]),
                    "iam_users": 0,
                    "s3_buckets": 0,
                    "securityhub_findings": high_count + critical_count,
                    "guardduty_findings": 0,
                    "kev_cves": kev_count,
                    "remediation_actions": len(remediation_playbook),
                    "critical_vulnerabilities": critical_count
                }

                snapshot_path = save_scan_snapshot(
                    summary=snapshot_summary,
                    assets=snapshot_assets,
                    remediation=remediation_playbook
                )

                st.success(
                    f"Snapshot saved: {snapshot_path.get('file_path')} "
                    f"(old snapshots deleted: {snapshot_path.get('deleted_old_snapshots', 0)})"
                )

            except Exception as snapshot_error:
                st.warning(f"Snapshot save skipped: {snapshot_error}")

            st.session_state["last_scan_status"] = "Completed"
            st.session_state["last_scan_time"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            if selected_client_data:
                st.success(
                    f"Scan completed for client: {selected_client_data[1]}"
                )
            else:
                st.success(
                    "Scan completed for DGS Internal AWS Environment"
                )

        except Exception as e:
            st.session_state["last_scan_status"] = "Failed"
            st.error(f"Scan failed: {e}")

st.info(
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

st.caption(
    "Scheduled scanning readiness is prepared for future cron, GitHub Actions, or cloud scheduler integration."
)

# ===========================================================
# EXECUTIVE SECURITY OVERVIEW
# ============================================================

st.header("Executive Security Overview")

metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)

metric_col1.metric("Critical Findings", critical_count)
metric_col2.metric("KEV Findings", kev_count)
metric_col3.metric("Average Risk Score", avg_risk)
metric_col4.metric("Risk Rating", risk_rating)

gauge_fig = go.Figure(
    go.Indicator(
        mode="gauge+number",
        value=avg_risk,
        title={"text": "Enterprise Security Risk Gauge"},
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

st.caption(identity.get("Arn", ""))

if enable_org_discovery:
    st.subheader("AWS Organization Accounts")

    organization_accounts = get_organization_data()

    if organization_accounts:
        org_df = pd.DataFrame(organization_accounts)
        st.dataframe(org_df, width="stretch")

        active_accounts = len(org_df[org_df["Status"] == "ACTIVE"])
        suspended_accounts = len(org_df[org_df["Status"] != "ACTIVE"])

        org_col1, org_col2, org_col3 = st.columns(3)
        org_col1.metric("Organization Accounts", len(org_df))
        org_col2.metric("Active Accounts", active_accounts)
        org_col3.metric("Suspended Accounts", suspended_accounts)
    else:
        st.info(
            "No AWS Organization accounts available or Organizations is not enabled."
        )


# ============================================================
# AWS GUARDDUTY THREAT INTELLIGENCE
# ============================================================

st.subheader("AWS GuardDuty Threat Intelligence")

guardduty_findings = get_guardduty_data()

if guardduty_findings:
    gd_df = pd.DataFrame(guardduty_findings)
    st.dataframe(gd_df, width="stretch")

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
    st.info("No GuardDuty findings available or GuardDuty is not enabled.")


# ============================================================
# SAVED THREAT FINDINGS
# ============================================================

st.subheader("Saved Threat Findings")

if not df.empty:
    st.dataframe(
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
    st.warning("No saved findings yet. Run the autonomous scanner first.")
    st.code("python headless_scan.py", language="bash")


# ============================================================
# REMEDIATION PRIORITY MATRIX
# ============================================================

st.subheader("Remediation Priority Matrix")

if remediation_playbook:
    remediation_df = pd.DataFrame(remediation_playbook)
    st.dataframe(remediation_df, width="stretch")
else:
    st.info("No remediation priorities available yet.")


# ============================================================
# AI EXECUTIVE RISK SUMMARY
# ============================================================

st.subheader("AI Executive Risk Summary")

st.markdown(risk_narrative)

with st.expander("AI Executive Analysis", expanded=True):
    st.markdown(ai_analysis)


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

st.subheader("MITRE ATT&CK Mapping")

mitre_df = build_mitre_mapping(df)

if not mitre_df.empty:
    st.dataframe(mitre_df, width="stretch")
else:
    st.info("No MITRE mappings available yet.")


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
    from asset_db import get_assets

    pdf_clients = get_clients()
    pdf_assets = get_assets()

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
