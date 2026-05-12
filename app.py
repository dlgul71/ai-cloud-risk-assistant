# =========================================================
# DGS SENTINEL AI
# AI-Powered Cloud Exposure Management Platform
# =========================================================

# -----------------------------
# IMPORT REQUIRED LIBRARIES
# -----------------------------

import os
from datetime import datetime

import boto3
import pandas as pd
import plotly.express as px
import streamlit as st

from dotenv import load_dotenv
from openai import OpenAI


# -----------------------------
# LOAD ENVIRONMENT VARIABLES
# -----------------------------

load_dotenv()

# AWS Region
region = os.getenv("AWS_REGION", "us-east-1")

# OpenAI API Key
openai_key = os.getenv("OPENAI_API_KEY")


# -----------------------------
# INITIALIZE AWS CLIENTS
# -----------------------------

# EC2 Client
ec2 = boto3.client(
    "ec2",
    region_name=region
)

# IAM Client
iam = boto3.client("iam")


# -----------------------------
# INITIALIZE OPENAI CLIENT
# -----------------------------

client = OpenAI(
    api_key=openai_key
)


# =========================================================
# FUNCTION:
# GET EC2 INSTANCES + RISK ANALYSIS
# =========================================================

def get_ec2_instances():

    # Pull all EC2 instances
    response = ec2.describe_instances()

    # Store all processed assets
    instances = []

    # Loop through reservations
    for reservation in response["Reservations"]:

        # Loop through each instance
        for instance in reservation["Instances"]:

            # Default risk settings
            risk = "Low"
            risk_reason = "Private/internal asset"

            # Store dangerous ports
            dangerous_ports = []

            # Store open ports
            open_ports = []

            # ---------------------------------
            # CHECK SECURITY GROUPS
            # ---------------------------------

            for sg in instance.get(
                "SecurityGroups",
                []
            ):

                sg_id = sg["GroupId"]

                # Pull SG details
                sg_details = ec2.describe_security_groups(
                    GroupIds=[sg_id]
                )

                # Loop through SG rules
                for group in sg_details["SecurityGroups"]:

                    for permission in group.get(
                        "IpPermissions",
                        []
                    ):

                        from_port = permission.get(
                            "FromPort"
                        )

                        # Save open ports
                        if from_port:
                            open_ports.append(
                                str(from_port)
                            )

                        # Check exposed CIDRs
                        for ip_range in permission.get(
                            "IpRanges",
                            []
                        ):

                            cidr = ip_range.get(
                                "CidrIp"
                            )

                            # Public internet exposure
                            if cidr == "0.0.0.0/0":

                                # SSH Exposure
                                if from_port == 22:

                                    dangerous_ports.append(
                                        "SSH (22) open to world"
                                    )

                                    risk = "Critical"

                                    risk_reason = (
                                        "SSH exposed to internet"
                                    )

                                # RDP Exposure
                                elif from_port == 3389:

                                    dangerous_ports.append(
                                        "RDP (3389) open to world"
                                    )

                                    risk = "Critical"

                                    risk_reason = (
                                        "RDP exposed to internet"
                                    )

            # ---------------------------------
            # CHECK PUBLIC IP EXPOSURE
            # ---------------------------------

            if (
                instance.get("PublicIpAddress")
                and risk != "Critical"
            ):

                risk = "High"

                risk_reason = (
                    "Public IP exposed to internet"
                )

            # ---------------------------------
            # STORE INSTANCE DATA
            # ---------------------------------

            instances.append({

                "InstanceId": instance.get(
                    "InstanceId"
                ),

                "State": instance["State"]["Name"],

                "InstanceType": instance.get(
                    "InstanceType"
                ),

                "PublicIp": instance.get(
                    "PublicIpAddress",
                    "None"
                ),

                "PrivateIp": instance.get(
                    "PrivateIpAddress",
                    "None"
                ),

                "SecurityGroups": ", ".join(
                    [
                        sg["GroupName"]
                        for sg in instance.get(
                            "SecurityGroups",
                            []
                        )
                    ]
                ),

                "SecurityGroupIds": ", ".join(
                    [
                        sg["GroupId"]
                        for sg in instance.get(
                            "SecurityGroups",
                            []
                        )
                    ]
                ),

                "OpenPorts": ", ".join(
                    open_ports
                ),

                "Risk": risk,

                "RiskReason": risk_reason,

                "DangerousPorts": ", ".join(
                    dangerous_ports
                )

            })

    return instances


# =========================================================
# FUNCTION:
# GET IAM USERS
# =========================================================

def get_iam_users():

    response = iam.list_users()

    users = []

    for user in response["Users"]:

        users.append({

            "UserName": user.get(
                "UserName"
            ),

            "UserId": user.get(
                "UserId"
            ),

            "CreateDate": str(
                user.get("CreateDate")
            ),

            "Arn": user.get(
                "Arn"
            )

        })

    return users


# =========================================================
# FUNCTION:
# AI SECURITY ANALYSIS
# =========================================================

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

                "content": (
                    "You are an AWS cloud security and CAASM expert."
                )
            },

            {
                "role": "user",

                "content": prompt
            }

        ]

    )

    return response.choices[0].message.content


# =========================================================
# STREAMLIT PAGE CONFIG
# =========================================================

st.set_page_config(

    page_title="DGS Sentinel AI",

    page_icon="🛡️",

    layout="wide"

)


# =========================================================
# CUSTOM CSS STYLING
# =========================================================

st.markdown(
    """
    <style>

    .stApp {
        background-color: #0b1020;
        color: white;
    }

    h1, h2, h3 {
        color: white;
    }

    div[data-testid="metric-container"] {
        background: linear-gradient(
            135deg,
            #111827,
            #1f2937
        );

        border: 1px solid #374151;

        padding: 20px;

        border-radius: 15px;

        box-shadow: 0 0 15px rgba(0,0,0,0.4);
    }

    div.stButton > button {

        background: linear-gradient(
            90deg,
            #2563eb,
            #7c3aed
        );

        color: white;

        border: none;

        border-radius: 10px;

        padding: 12px 24px;

        font-weight: bold;
    }

    div.stButton > button:hover {

        background: linear-gradient(
            90deg,
            #1d4ed8,
            #6d28d9
        );
    }

    </style>
    """,

    unsafe_allow_html=True

)


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.title("🛡️ DGS Sentinel AI")

    st.caption(
        "AI-Powered Cloud Exposure Management"
    )

    st.markdown("---")

    st.write("### Navigation")

    st.write("• Overview")
    st.write("• EC2 Assets")
    st.write("• IAM Visibility")
    st.write("• Open Ports")
    st.write("• AI Risk Analysis")
    st.write("• Reports")

    st.markdown("---")

    risk_filter = st.selectbox(

        "Filter by Risk",

        [
            "All",
            "Critical",
            "High",
            "Medium",
            "Low"
        ]

    )

    st.markdown("---")

    st.write("**David L. Gulledge**")

    st.caption(
        "Cybersecurity Consultant | Cloud Security Engineer"
    )


# =========================================================
# MAIN TITLE
# =========================================================

st.title("🛡️ DGS Sentinel AI")

st.caption(
    "AI-Powered Cloud Security Risk Assistant"
)

st.caption(
    f"Last Scan: {datetime.now().strftime('%B %d, %Y %I:%M %p')}"
)


# =========================================================
# MAIN SCAN BUTTON
# =========================================================

if st.button(
    "Scan AWS Environment",
    key="main_scan_button"
):

    # Pull AWS assets
    instances = get_ec2_instances()

    # Check if assets exist
    if instances:

        # Convert to DataFrame
        df = pd.DataFrame(instances)

        # Apply risk filter
        if risk_filter != "All":

            df = df[
                df["Risk"] == risk_filter
            ]

        # =================================================
        # METRICS
        # =================================================

        total_assets = len(df)

        high_risk_assets = len(
            df[df["Risk"].isin(
                ["High", "Critical"]
            )]
        )

        public_assets = len(
            df[df["PublicIp"] != "None"]
        )

        secure_assets = len(
            df[df["Risk"] == "Low"]
        )

        # =================================================
        # ENVIRONMENT RISK BANNER
        # =================================================

        if "Critical" in df["Risk"].values:

            st.error(
                "🚨 OVERALL ENVIRONMENT RISK: CRITICAL"
            )

        elif "High" in df["Risk"].values:

            st.warning(
                "⚠️ OVERALL ENVIRONMENT RISK: HIGH"
            )

        else:

            st.success(
                "✅ OVERALL ENVIRONMENT RISK: LOW"
            )

        # =================================================
        # METRIC CARDS
        # =================================================

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Total Assets",
            total_assets
        )

        col2.metric(
            "High/Critical Risk",
            high_risk_assets
        )

        col3.metric(
            "Public Assets",
            public_assets
        )

        col4.metric(
            "Secure Assets",
            secure_assets
        )

        # =================================================
        # PIE CHART
        # =================================================

        st.subheader("Risk Distribution")

        risk_counts = (
            df["Risk"]
            .value_counts()
            .reset_index()
        )

        risk_counts.columns = [
            "Risk",
            "Count"
        ]

        fig = px.pie(

            risk_counts,

            names="Risk",

            values="Count",

            hole=0.45,

            title="Cloud Risk Severity Distribution"

        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        # =================================================
        # EXPOSURE BAR CHART
        # =================================================

        st.subheader(
            "Asset Exposure Analytics"
        )

        exposure_df = pd.DataFrame({

            "Category": [
                "Public Assets",
                "Private Assets"
            ],

            "Count": [
                public_assets,
                total_assets - public_assets
            ]

        })

        exposure_fig = px.bar(

            exposure_df,

            x="Category",

            y="Count",

            title="Public vs Private Asset Exposure"

        )

        st.plotly_chart(
            exposure_fig,
            use_container_width=True
        )

        # =================================================
        # EC2 ASSET TABLE
        # =================================================

        st.subheader(
            "Discovered EC2 Assets"
        )

        # Risk highlighting
        def highlight_risk(val):

            if val == "Critical":
                return (
                    "background-color: darkred; color: white;"
                )

            elif val == "High":
                return (
                    "background-color: red; color: white;"
                )

            elif val == "Medium":
                return (
                    "background-color: orange; color: black;"
                )

            elif val == "Low":
                return (
                    "background-color: green; color: white;"
                )

            return ""

        styled_df = df.style.map(
            highlight_risk,
            subset=["Risk"]
        )

        st.dataframe(
            styled_df,
            use_container_width=True
        )

        # =================================================
        # CSV EXPORT
        # =================================================

        csv = df.to_csv(index=False)

        st.download_button(

            label="Download Security Findings CSV",

            data=csv,

            file_name="aws_security_findings.csv",

            mime="text/csv"

        )

        # =================================================
        # IAM VISIBILITY
        # =================================================

        st.subheader(
            "IAM User Visibility"
        )

        iam_users = get_iam_users()

        if iam_users:

            iam_df = pd.DataFrame(
                iam_users
            )

            st.dataframe(
                iam_df,
                use_container_width=True
            )

        else:

            st.warning(
                "No IAM users found."
            )

        # =================================================
        # AI INSIGHT CARD
        # =================================================

        st.info(
            """
🤖 AI SECURITY INSIGHT

This dashboard analyzes AWS EC2 exposure,
IAM visibility, open ports, security groups,
and risk severity to support cloud exposure
management and CAASM/CSPM workflows.
"""
        )

        # =================================================
        # AI ANALYSIS
        # =================================================

        st.subheader(
            "AI Security Risk Analysis"
        )

        with st.spinner(
            "Analyzing risk with AI..."
        ):

            analysis = analyze_risk(
                instances
            )

        st.write(analysis)

        # =================================================
        # FINAL RISK MESSAGE
        # =================================================

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

        # =================================================
        # FOOTER
        # =================================================

        st.markdown("---")

        st.markdown(
            """
**DGS Sentinel AI**  
AI-Powered Cloud Exposure Management Platform  
© 2026 Data Generated Solutions, LLC
"""
        )

    else:

        st.warning(
            "No EC2 instances found."
        )