import os
from datetime import datetime

import boto3
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI


# ======================================================
# PAGE CONFIG
# ======================================================

st.set_page_config(
    page_title="DGS Sentinel AI",
    page_icon="🛡️",
    layout="wide"
)


# ======================================================
# CUSTOM CSS
# ======================================================

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #07111f, #111827);
        color: white;
    }

    h1, h2, h3, h4 {
        color: white;
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f172a, #111827);
    }

    div[data-testid="metric-container"] {
        background: linear-gradient(135deg, #111827, #1f2937);
        border: 1px solid #374151;
        padding: 18px;
        border-radius: 16px;
        box-shadow: 0 0 16px rgba(59, 130, 246, 0.15);
    }

    div.stButton > button {
        background: linear-gradient(90deg, #2563eb, #7c3aed);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 10px 22px;
        font-weight: 700;
    }

    div.stButton > button:hover {
        background: linear-gradient(90deg, #1d4ed8, #6d28d9);
        color: white;
    }

    .ai-insight {
        background: linear-gradient(135deg, #132238, #0f172a);
        border-left: 5px solid #3b82f6;
        padding: 18px;
        border-radius: 12px;
        color: white;
        margin-top: 12px;
        margin-bottom: 18px;
        box-shadow: 0 0 18px rgba(59, 130, 246, 0.2);
    }

    .footer {
        color: #94a3b8;
        font-size: 14px;
        margin-top: 40px;
        border-top: 1px solid #334155;
        padding-top: 15px;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ======================================================
# LOAD ENVIRONMENT VARIABLES
# ======================================================

load_dotenv()

region = os.getenv("AWS_REGION", "us-east-1")
openai_key = os.getenv("OPENAI_API_KEY")


# ======================================================
# AWS / OPENAI CLIENTS
# ======================================================

ec2 = boto3.client("ec2", region_name=region)
iam = boto3.client("iam")
client = OpenAI(api_key=openai_key)


# ======================================================
# FUNCTIONS
# ======================================================

def get_ec2_instances():
    response = ec2.describe_instances()
    instances = []

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):

            risk = "Low"
            risk_reason = "Private/internal asset"
            dangerous_ports = []
            open_ports = []

            for sg in instance.get("SecurityGroups", []):
                sg_id = sg["GroupId"]

                sg_details = ec2.describe_security_groups(
                    GroupIds=[sg_id]
                )

                for group in sg_details.get("SecurityGroups", []):
                    for permission in group.get("IpPermissions", []):

                        from_port = permission.get("FromPort")

                        if from_port:
                            open_ports.append(str(from_port))

                        for ip_range in permission.get("IpRanges", []):
                            cidr = ip_range.get("CidrIp")

                            if cidr == "0.0.0.0/0":

                                if from_port == 22:
                                    dangerous_ports.append(
                                        "SSH (22) open to world"
                                    )
                                    risk = "Critical"
                                    risk_reason = "SSH exposed to internet"

                                elif from_port == 3389:
                                    dangerous_ports.append(
                                        "RDP (3389) open to world"
                                    )
                                    risk = "Critical"
                                    risk_reason = "RDP exposed to internet"

            if instance.get("PublicIpAddress") and risk != "Critical":
                risk = "High"
                risk_reason = "Public IP exposed to internet"

            instances.append({
                "InstanceId": instance.get("InstanceId"),
                "State": instance.get("State", {}).get("Name"),
                "InstanceType": instance.get("InstanceType"),
                "PublicIp": instance.get("PublicIpAddress", "None"),
                "PrivateIp": instance.get("PrivateIpAddress", "None"),
                "SecurityGroups": ", ".join(
                    [sg["GroupName"] for sg in instance.get("SecurityGroups", [])]
                ),
                "SecurityGroupIds": ", ".join(
                    [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                ),
                "OpenPorts": ", ".join(sorted(set(open_ports))),
                "Risk": risk,
                "RiskReason": risk_reason,
                "DangerousPorts": ", ".join(dangerous_ports)
            })

    return instances


def get_iam_users():
    response = iam.list_users()
    users = []

    for user in response.get("Users", []):
        users.append({
            "UserName": user.get("UserName"),
            "UserId": user.get("UserId"),
            "CreateDate": str(user.get("CreateDate")),
            "Arn": user.get("Arn")
        })

    return users


def analyze_risk(instances):
    prompt = f"""
You are a cloud security analyst.

Review these AWS EC2 assets and identify:
1. Executive summary
2. Security risks
3. Cloud exposure concerns
4. Compliance concerns
5. Remediation steps

Assets:
{instances}
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {
                "role": "system",
                "content": "You are an AWS cloud security, CAASM, CSPM, and risk management expert."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


def highlight_risk(val):
    if val == "Critical":
        return "background-color: darkred; color: white;"
    if val == "High":
        return "background-color: red; color: white;"
    if val == "Medium":
        return "background-color: orange; color: black;"
    if val == "Low":
        return "background-color: green; color: white;"
    return ""


# ======================================================
# SIDEBAR
# ======================================================

with st.sidebar:
    st.title("🛡️ DGS Sentinel AI")
    st.caption("AI-Powered Cloud Exposure Management")

    st.markdown("---")

    st.markdown("### Navigation")
    st.markdown("• Overview")
    st.markdown("• EC2 Assets")
    st.markdown("• IAM Visibility")
    st.markdown("• Open Ports")
    st.markdown("• AI Risk Analysis")
    st.markdown("• Reports")

    st.markdown("---")

    risk_filter = st.selectbox(
        "Filter by Risk",
        ["All", "Critical", "High", "Medium", "Low"]
    )

    st.markdown("---")

    st.markdown("**David L. Gulledge**")
    st.caption("Cybersecurity Consultant | Cloud Security Engineer")


# ======================================================
# HEADER
# ======================================================

st.title("🛡️ DGS Sentinel AI")
st.caption("AI-Powered Cloud Security Risk Assistant")

st.write(
    "Cloud Exposure Management, AWS Asset Visibility, IAM Intelligence, "
    "Open Port Detection, and AI-Driven Risk Analysis."
)

st.caption(f"Last Scan Session: {datetime.now().strftime('%B %d, %Y %I:%M %p')}")


# ======================================================
# MAIN DASHBOARD
# ======================================================

if st.button("Scan AWS Environment", key="main_scan_button"):

    instances = get_ec2_instances()

    if not instances:
        st.warning("No EC2 instances found.")

    else:
        df = pd.DataFrame(instances)

        if risk_filter != "All":
            df = df[df["Risk"] == risk_filter]

        total_assets = len(df)

        high_risk_assets = len(
            df[df["Risk"].isin(["High", "Critical"])]
        )

        public_assets = len(
            df[df["PublicIp"] != "None"]
        )

        secure_assets = len(
            df[df["Risk"] == "Low"]
        )

        # ======================================================
        # RISK BANNER
        # ======================================================

        if "Critical" in df["Risk"].values:
            st.error("🚨 OVERALL ENVIRONMENT RISK: CRITICAL")
            risk_score = 35
        elif "High" in df["Risk"].values:
            st.warning("⚠️ OVERALL ENVIRONMENT RISK: HIGH")
            risk_score = 65
        else:
            st.success("✅ OVERALL ENVIRONMENT RISK: LOW")
            risk_score = 92

        # ======================================================
        # KPI METRICS
        # ======================================================

        col1, col2, col3, col4, col5 = st.columns(5)

        col1.metric("Total Assets", total_assets)
        col2.metric("High/Critical Risk", high_risk_assets)
        col3.metric("Public Assets", public_assets)
        col4.metric("Secure Assets", secure_assets)
        col5.metric("Risk Score", f"{risk_score}/100")

        # ======================================================
        # RISK DISTRIBUTION DONUT CHART
        # ======================================================

        st.markdown("## Risk Distribution")

        risk_counts = df["Risk"].value_counts()

        risk_chart_df = pd.DataFrame({
            "Risk": risk_counts.index,
            "Count": risk_counts.values
        })

        donut_fig = px.pie(
            risk_chart_df,
            names="Risk",
            values="Count",
            hole=0.55,
            title="Cloud Risk Severity Distribution",
            color="Risk",
            color_discrete_map={
                "Critical": "#7f1d1d",
                "High": "#ef4444",
                "Medium": "#f59e0b",
                "Low": "#10b981"
            }
        )

        donut_fig.update_layout(
            paper_bgcolor="#0b1020",
            plot_bgcolor="#0b1020",
            font_color="white",
            title_font_color="white"
        )

        st.plotly_chart(
            donut_fig,
            use_container_width=True
        )

        # ======================================================
        # ASSET EXPOSURE ANALYTICS
        # ======================================================

        st.markdown("## Asset Exposure Analytics")

        exposure_df = pd.DataFrame({
            "Category": ["Public Assets", "Private/Secure Assets"],
            "Count": [public_assets, secure_assets]
        })

        exposure_fig = px.bar(
            exposure_df,
            x="Category",
            y="Count",
            color="Category",
            title="Asset Exposure Overview",
            color_discrete_map={
                "Public Assets": "#ef4444",
                "Private/Secure Assets": "#10b981"
            }
        )

        exposure_fig.update_layout(
            paper_bgcolor="#0b1020",
            plot_bgcolor="#0b1020",
            font_color="white",
            title_font_color="white"
        )

        st.plotly_chart(
            exposure_fig,
            use_container_width=True
        )

        # ======================================================
        # OPEN PORT ANALYTICS
        # ======================================================

        st.markdown("## Open Port Analytics")

        port_counts = {}

        for ports in df["OpenPorts"]:
            if ports:
                for port in str(ports).split(","):
                    port = port.strip()

                    if port:
                        port_counts[port] = port_counts.get(port, 0) + 1

        if port_counts:
            ports_df = pd.DataFrame({
                "Port": list(port_counts.keys()),
                "Count": list(port_counts.values())
            })

            port_fig = px.bar(
                ports_df,
                x="Port",
                y="Count",
                color="Port",
                title="Detected Open Ports"
            )

            port_fig.update_layout(
                paper_bgcolor="#0b1020",
                plot_bgcolor="#0b1020",
                font_color="white",
                title_font_color="white"
            )

            st.plotly_chart(
                port_fig,
                use_container_width=True
            )

        else:
            st.success("No open ports detected.")

        # ======================================================
        # EC2 ASSET TABLE
        # ======================================================

        st.markdown("## Discovered EC2 Assets")

        styled_df = df.style.map(
            highlight_risk,
            subset=["Risk"]
        )

        st.dataframe(
            styled_df,
            use_container_width=True
        )

        csv = df.to_csv(index=False)

        st.download_button(
            label="Download Security Findings CSV",
            data=csv,
            file_name="aws_security_findings.csv",
            mime="text/csv"
        )

        # ======================================================
        # IAM VISIBILITY
        # ======================================================

        st.markdown("## IAM User Visibility")

        iam_users = get_iam_users()

        if iam_users:
            iam_df = pd.DataFrame(iam_users)

            st.dataframe(
                iam_df,
                use_container_width=True
            )
        else:
            st.warning("No IAM users found.")

        # ======================================================
        # AI SECURITY INSIGHT CARD
        # ======================================================

        st.markdown("## AI Security Insight")

        if high_risk_assets == 0:
            insight = """
            No high-risk public exposure detected.
            No dangerous open ports identified.
            Cloud posture currently aligns with a low-risk configuration.
            """
        else:
            insight = f"""
            Public exposure detected on {public_assets} asset(s).
            High or critical risk assets were identified.
            Review security group ingress rules, restrict SSH/RDP access,
            and enforce least privilege IAM controls.
            """

        st.markdown(
            f"""
            <div class="ai-insight">
                <h4>🤖 AI SECURITY INSIGHT</h4>
                <p>{insight}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        # ======================================================
        # OPENAI ANALYSIS
        # ======================================================

        st.markdown("## AI Security Risk Analysis")

        with st.spinner("Analyzing risk with AI..."):
            analysis = analyze_risk(instances)

        st.write(analysis)

        if "Critical" in df["Risk"].values:
            st.error(
                "Critical exposure detected. Immediate remediation recommended."
            )
        elif "High" in df["Risk"].values:
            st.warning(
                "High-risk assets detected. Review security groups and access controls."
            )
        else:
            st.success(
                "No critical cloud exposures detected."
            )


# ======================================================
# FOOTER
# ======================================================

st.markdown(
    """
    <div class="footer">
        DGS Sentinel AI © 2026 | AI-Powered Cloud Exposure Management Platform |
        Built by David L. Gulledge
    </div>
    """,
    unsafe_allow_html=True
)