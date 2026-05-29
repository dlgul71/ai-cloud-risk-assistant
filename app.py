# ============================================================
# DGS SENTINEL AI
# AI-Powered CAASM / CSPM / CNAPP / SIEM Platform
# Clean Stable Streamlit Application
# ============================================================

from datetime import datetime
from io import BytesIO

import hmac
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from guardduty_ingest import get_guardduty_findings
from org_ingest import get_organization_accounts
from datetime import datetime, timedelta

try:
    from db import get_all_findings
except Exception:
    get_all_findings = None

try:
    from scan_engine import run_scan
except Exception:
    run_scan = None

try:
    from streamlit_autorefresh import st_autorefresh
    AUTOREFRESH_AVAILABLE = True
except Exception:
    AUTOREFRESH_AVAILABLE = False


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="DGS Sentinel AI",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CONFIG
# ============================================================

COMPANY_NAME = "Data Generated Solutions, LLC"


# ============================================================
# UTILITY FUNCTIONS
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

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        correct_username = st.secrets["auth"]["username"]
        correct_password = st.secrets["auth"]["password"]

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

def safe_get_findings():
    """Safely load saved findings from db.py."""
    if get_all_findings is None:
        return []

    try:
        return get_all_findings()
    except Exception as e:
        st.warning(f"Unable to load saved findings: {e}")
        return []
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
    if avg_risk >= 75:
        return "CRITICAL RISK"
    if avg_risk >= 50:
        return "HIGH RISK"
    if avg_risk >= 25:
        return "MODERATE RISK"
    return "LOW RISK"


def generate_pdf(ai_analysis, summary, remediation_playbook, risk_narrative=""):
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

    # Header
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


def highlight_priority(row):
    if row["Priority"] == "CRITICAL":
        return ["background-color: #ffcccc"] * len(row)
    if row["Priority"] == "HIGH":
        return ["background-color: #ffe0b3"] * len(row)
    return [""] * len(row)


def build_mitre_mapping(df):
    mitre_rows = []

    for _, row in df.iterrows():
        if row["KEV Exploited"] == 1:
            mitre_rows.append({
                "CVE ID": row["CVE ID"],
                "Technique": "T1190 - Exploit Public-Facing Application",
                "Tactic": "Initial Access",
                "Priority": row["Priority"],
                "Risk Score": row["Risk Score"]
            })
        else:
            mitre_rows.append({
                "CVE ID": row["CVE ID"],
                "Technique": "T1595 - Active Scanning",
                "Tactic": "Reconnaissance",
                "Priority": row["Priority"],
                "Risk Score": row["Risk Score"]
            })

    return pd.DataFrame(mitre_rows)


def build_remediation_matrix(df):
    remediation_df = df.copy()

    remediation_df["Remediation Priority"] = remediation_df.apply(
        lambda row: "Immediate Action"
        if row["Priority"] == "CRITICAL" and row["KEV Exploited"] == 1
        else "Standard Remediation",
        axis=1
    )

    remediation_df["Business Impact"] = remediation_df["Risk Score"].apply(
        lambda score: "High Business Risk"
        if score >= 75
        else "Moderate Business Risk"
        if score >= 40
        else "Low Business Risk"
    )

    return remediation_df[
        [
            "CVE ID",
            "Priority",
            "Risk Score",
            "KEV Exploited",
            "Known Ransomware",
            "Remediation Priority",
            "Business Impact",
            "Required Action",
        ]
    ]


# ============================================================
# MAIN HEADER
# ============================================================

st.title("🛡️ DGS Sentinel AI")
st.caption("AI-Powered CAASM / CSPM / CNAPP / SIEM Platform")


# ============================================================
# MANUAL AUTONOMOUS SCAN
# ============================================================

st.subheader("Manual Autonomous Scan")

if "last_scan_status" not in st.session_state:
    st.session_state["last_scan_status"] = "Idle"

if "last_scan_time" not in st.session_state:
    st.session_state["last_scan_time"] = "Never"

if st.button("Run DGS Sentinel Scan Now", type="primary"):
    st.session_state["last_scan_status"] = "Running"

    with st.spinner("Running autonomous scan..."):
        try:
            if run_scan is None:
                raise RuntimeError("scan_engine.run_scan is not available.")

            run_scan()

            st.session_state["last_scan_status"] = "Completed"
            st.session_state["last_scan_time"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            st.success(
                "Scan completed successfully. Refresh dashboard to view updated findings."
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


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:
    
    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()
    
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

    auto_scan_enabled = st.toggle(
        "Auto-Refresh Scan Readiness",
        value=False,
        help="Refreshes the dashboard page on an interval.",
        key="toggle_auto_scan_enabled"
    )

    auto_refresh = st.toggle(
        "Enable Live Dashboard Refresh",
        value=False,
        key="live_refresh_toggle"
    )

    refresh_interval = st.slider(
        "Refresh Interval (Seconds)",
        min_value=10,
        max_value=300,
        value=60,
        step=10,
        key="refresh_interval_slider"
    )

    st.markdown("---")
    st.subheader("Autonomous Monitoring")
    st.write(f"Last Scan: {st.session_state.get('last_scan_time', 'Never')}")
    st.write(f"Status: {st.session_state.get('last_scan_status', 'Idle')}")

if auto_refresh:
    if AUTOREFRESH_AVAILABLE:
        st_autorefresh(
            interval=refresh_interval * 1000,
            key="sentinel_auto_refresh"
        )
        st.success(
            f"Live SOC Mode Enabled - Refreshing every {refresh_interval} seconds"
        )
    else:
        st.warning(
            "streamlit-autorefresh is not installed. Run: pip install streamlit-autorefresh"
        )


# ============================================================
# LOAD SAVED FINDINGS
# ============================================================

rows = safe_get_findings()

st.header("Executive Security Overview")
st.subheader("AWS GuardDuty Threat Intelligence")

guardduty_findings = get_guardduty_findings()

if guardduty_findings:

    gd_df = pd.DataFrame(guardduty_findings)

    st.dataframe(
        gd_df,
        width="stretch"
    )

    high_gd = len(
        gd_df[gd_df["Severity"] >= 7]
    )

    medium_gd = len(
        gd_df[
            (gd_df["Severity"] >= 4) &
            (gd_df["Severity"] < 7)
        ]
    )

    gd_col1, gd_col2 = st.columns(2)

    gd_col1.metric(
        "High Severity Threats",
        high_gd
    )

    gd_col2.metric(
        "Medium Severity Threats",
        medium_gd
    )

else:

    st.info(
        "No GuardDuty findings available or GuardDuty is not enabled."
    )
if rows:
    df = pd.DataFrame(rows, columns=[
        "Scan Time",
        "CVE ID",
        "Priority",
        "Risk Score",
        "KEV Exploited",
        "Known Ransomware",
        "Required Action"
    ])

    df["Scan Time"] = pd.to_datetime(
        df["Scan Time"],
        errors="coerce"
    )

    df = df.dropna(subset=["Scan Time"])

    critical_count = len(df[df["Priority"] == "CRITICAL"])
    kev_count = len(df[df["KEV Exploited"] == 1])
    avg_risk = round(df["Risk Score"].mean(), 2)
    risk_rating = calculate_risk_rating(avg_risk)

    # AWS visibility summary
    st.subheader("AWS Account Visibility")
    # ============================================================
# AWS ORGANIZATION ACCOUNT AGGREGATION
# ============================================================

    # ============================================================
    # AWS ORGANIZATION ACCOUNT AGGREGATION
    # ============================================================

    st.subheader("AWS Organization Accounts")

    organization_accounts = get_organization_accounts()

    if organization_accounts:

        org_df = pd.DataFrame(organization_accounts)

        st.dataframe(
            org_df,
            width="stretch"
        )

        active_accounts = len(
            org_df[org_df["Status"] == "ACTIVE"]
        )

        suspended_accounts = len(
            org_df[org_df["Status"] != "ACTIVE"]
        )

        org_col1, org_col2, org_col3 = st.columns(3)

        org_col1.metric(
            "Organization Accounts",
            len(org_df)
        )

        org_col2.metric(
            "Active Accounts",
            active_accounts
        )

        org_col3.metric(
            "Suspended Accounts",
            suspended_accounts
        )

    else:

        st.info(
            "No AWS Organization accounts available or Organizations is not enabled."
        )
    account_col1, account_col2, account_col3, account_col4 = st.columns(4)

    account_col1.metric("AWS Accounts", 1)
    account_col2.metric("Assets Discovered", len(df))
    account_col3.metric("Critical Assets", critical_count)
    account_col4.metric("KEV Findings", kev_count)

    st.divider()

    # Executive KPIs
    metric_col1, metric_col2, metric_col3 = st.columns(3)
    metric_col1.metric("Critical Findings", critical_count)
    metric_col2.metric("Known Exploited CVEs", kev_count)
    metric_col3.metric("Average Risk Score", avg_risk)

    st.subheader("Enterprise Security Risk Gauge")

    gauge_fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=avg_risk,
        title={"text": "Average Enterprise Risk"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "red"},
            "steps": [
                {"range": [0, 25], "color": "green"},
                {"range": [25, 50], "color": "yellow"},
                {"range": [50, 75], "color": "orange"},
                {"range": [75, 100], "color": "red"},
            ],
        },
    ))

    gauge_fig.update_layout(
        height=350,
        paper_bgcolor="#0F172A",
        font_color="white",
    )

    st.plotly_chart(
        gauge_fig,
        use_container_width=True
    )

    # Findings table
    st.subheader("Saved Threat Findings")

    st.dataframe(
        df.style.apply(highlight_priority, axis=1),
        width="stretch"
    )

    # Risk trend
    st.subheader("Risk Trend Over Time")

    risk_trend = (
        df.groupby("Scan Time")["Risk Score"]
        .mean()
        .reset_index()
    )

    st.line_chart(
        risk_trend,
        x="Scan Time",
        y="Risk Score"
    )

    # Top threats
    st.subheader("Top Threats by Risk Score")

    top_threats = (
        df.sort_values(by="Risk Score", ascending=False)
        .head(10)
    )

    st.bar_chart(
        top_threats,
        x="CVE ID",
        y="Risk Score",
    )

    # Heatmap
    st.subheader("Live Attack Surface Heatmap")

    heatmap_df = df.copy()
    heatmap_df["Exposure"] = heatmap_df["KEV Exploited"].apply(
        lambda x: "Known Exploited" if x == 1 else "Observed"
    )

    heatmap_chart = px.density_heatmap(
        heatmap_df,
        x="Priority",
        y="Exposure",
        z="Risk Score",
        histfunc="avg",
        color_continuous_scale="Reds",
        title="Threat Exposure Heatmap"
    )

    heatmap_chart.update_layout(
        paper_bgcolor="#0F172A",
        plot_bgcolor="#0F172A",
        font_color="white",
        height=500,
    )

    st.plotly_chart(
        heatmap_chart,
        use_container_width=True
    )

    # Severity pie
    st.subheader("Threat Severity Distribution")

    severity_counts = (
        df["Priority"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = ["Priority", "Count"]

    severity_chart = px.pie(
        severity_counts,
        names="Priority",
        values="Count",
        title="Threat Severity Breakdown",
        hole=0.45,
        color="Priority",
        color_discrete_map={
            "CRITICAL": "#DC2626",
            "HIGH": "#F97316",
            "MODERATE": "#FACC15",
            "LOW": "#22C55E",
            "STANDARD": "#94A3B8",
        }
    )

    severity_chart.update_layout(
        paper_bgcolor="#0F172A",
        font_color="white",
        height=500,
    )

    st.plotly_chart(
        severity_chart,
        use_container_width=True
    )

    # Remediation matrix
    st.subheader("Remediation Priority Matrix")

    matrix_view = build_remediation_matrix(df)

    st.dataframe(
        matrix_view,
        width="stretch"
    )

    # Security timeline
    st.subheader("Security Operations Timeline")

    timeline_df = df.copy()

    timeline_df["Event"] = timeline_df.apply(
        lambda row: f"{row['Priority']} - {row['CVE ID']}",
        axis=1
    )

    timeline_df["Scan Time"] = pd.to_datetime(
        timeline_df["Scan Time"],
        errors="coerce"
    )

    timeline_df = timeline_df.dropna(subset=["Scan Time"])
    timeline_df["End Time"] = timeline_df["Scan Time"] + pd.Timedelta(minutes=5)

    timeline_chart = px.timeline(
        timeline_df,
        x_start="Scan Time",
        x_end="End Time",
        y="Event",
        color="Priority",
        title="Threat Detection Timeline",
        color_discrete_map={
            "CRITICAL": "#DC2626",
            "HIGH": "#F97316",
            "MODERATE": "#FACC15",
            "LOW": "#22C55E",
            "STANDARD": "#94A3B8",
        }
    )

    timeline_chart.update_layout(
        paper_bgcolor="#0F172A",
        plot_bgcolor="#0F172A",
        font_color="white",
        height=500,
    )

    st.plotly_chart(
        timeline_chart,
        use_container_width=True
    )

    # Exports
    st.subheader("Export Executive Evidence")

    csv_findings = df.to_csv(index=False).encode("utf-8")
    csv_matrix = matrix_view.to_csv(index=False).encode("utf-8")

    saved_summary = {
        "security_score": int(max(100 - avg_risk, 0)),
        "risk_rating": risk_rating,
        "assets": len(df),
        "critical_findings": critical_count,
        "kev_cves": kev_count,
        "remediation_actions": len(matrix_view),
    }

    saved_risk_narrative = f"""
DGS Sentinel AI identified {len(df)} saved threat findings from the autonomous scan history.

The current average risk score is {avg_risk}. The dashboard shows {critical_count} critical findings and {kev_count} known exploited vulnerabilities.

Priority should be given to KEV-exploited vulnerabilities, ransomware-associated findings, and high business impact vulnerabilities.
"""

    saved_ai_analysis = """
DGS Sentinel AI recommends prioritizing remediation of critical KEV-exploited vulnerabilities, validating exposure paths, applying vendor patches, documenting remediation evidence, and re-running autonomous scans after remediation.
"""

    pdf_report = generate_pdf(
        saved_ai_analysis,
        saved_summary,
        matrix_view.to_dict("records"),
        saved_risk_narrative
    )

    export_col1, export_col2, export_col3 = st.columns(3)

    export_col1.download_button(
        label="Threat Findings CSV",
        data=csv_findings,
        file_name="dgs_sentinel_threat_findings.csv",
        mime="text/csv",
        use_container_width=True
    )

    export_col2.download_button(
        label="Remediation Matrix CSV",
        data=csv_matrix,
        file_name="dgs_sentinel_remediation_matrix.csv",
        mime="text/csv",
        use_container_width=True
    )

    export_col3.download_button(
        label="Executive PDF Report",
        data=pdf_report,
        file_name="dgs_sentinel_executive_report.pdf",
        mime="application/pdf",
        use_container_width=True
    )

    # AI remediation summary
    st.subheader("AI Executive Remediation Summary")

    critical_findings = df[df["Priority"] == "CRITICAL"]

    if not critical_findings.empty:
        st.markdown("""
**Executive Risk Summary**

DGS Sentinel AI identified known exploited vulnerability exposure in the environment.  
These findings should be treated as urgent because they are associated with active exploitation intelligence.

**Recommended Actions**

1. Prioritize remediation of all KEV-exploited CVEs.
2. Validate whether affected assets are internet-facing.
3. Apply vendor patches or remove affected systems from the network.
4. Review ransomware exposure and compensating controls.
5. Re-run the autonomous scan after remediation.
""")
    else:
        st.success("No critical KEV-exploited findings detected.")

    # MITRE mapping
    st.subheader("MITRE ATT&CK Mapping")

    mitre_df = build_mitre_mapping(df)

    st.dataframe(
        mitre_df,
        width="stretch"
    )

else:
    st.warning("No saved findings yet. Run the headless scanner first.")
    st.code("python headless_scan.py", language="bash")
    st.info(
        "Once the headless scan saves results to SQLite, this dashboard will show metrics, charts, remediation guidance, MITRE mapping, and export buttons."
    )
