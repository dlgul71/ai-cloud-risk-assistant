import os
import boto3
import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

region = os.getenv("AWS_REGION", "us-east-1")
openai_key = os.getenv("OPENAI_API_KEY")

ec2 = boto3.client("ec2", region_name=region)
iam = boto3.client("iam")
client = OpenAI(api_key=openai_key)


def get_ec2_instances():
    response = ec2.describe_instances()
    instances = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:

            risk = "Low"
            risk_reason = "Private/internal asset"
            dangerous_ports = []
            open_ports = []

            for sg in instance.get("SecurityGroups", []):
                sg_id = sg["GroupId"]

                sg_details = ec2.describe_security_groups(
                    GroupIds=[sg_id]
                )

                for group in sg_details["SecurityGroups"]:
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
                "State": instance["State"]["Name"],
                "InstanceType": instance.get("InstanceType"),
                "PublicIp": instance.get("PublicIpAddress", "None"),
                "PrivateIp": instance.get("PrivateIpAddress", "None"),

                "SecurityGroups": ", ".join(
                    [
                        sg["GroupName"]
                        for sg in instance.get("SecurityGroups", [])
                    ]
                ),

                "SecurityGroupIds": ", ".join(
                    [
                        sg["GroupId"]
                        for sg in instance.get("SecurityGroups", [])
                    ]
                ),

                "OpenPorts": ", ".join(open_ports),
                "Risk": risk,
                "RiskReason": risk_reason,
                "DangerousPorts": ", ".join(dangerous_ports)
            })

    return instances


def get_iam_users():
    response = iam.list_users()
    users = []

    for user in response["Users"]:
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
                "content": "You are an AWS cloud security and CAASM expert."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    return response.choices[0].message.content


st.set_page_config(
    page_title="AI Cloud Security Dashboard",
    layout="wide"
)

st.title("AI Cloud Security Risk Assistant")

st.write("AWS EC2 Asset Visibility + AI Risk Analysis")

risk_filter = st.sidebar.selectbox(
    "Filter by Risk",
    ["All", "Critical", "High", "Medium", "Low"]
)

if st.button("Scan AWS Environment", key="main_scan_button"):

    instances = get_ec2_instances()

    if instances:

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

        if "Critical" in df["Risk"].values:
            st.error("OVERALL ENVIRONMENT RISK: CRITICAL")
        elif "High" in df["Risk"].values:
            st.warning("OVERALL ENVIRONMENT RISK: HIGH")
        else:
            st.success("OVERALL ENVIRONMENT RISK: LOW")

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Assets", total_assets)
        col2.metric("High/Critical Risk", high_risk_assets)
        col3.metric("Public Assets", public_assets)
        col4.metric("Secure Assets", secure_assets)

        st.subheader("Discovered EC2 Assets")

        def highlight_risk(val):
            if val == "Critical":
                return "background-color: darkred; color: white;"
            elif val == "High":
                return "background-color: red; color: white;"
            elif val == "Medium":
                return "background-color: orange; color: black;"
            elif val == "Low":
                return "background-color: green; color: white;"
            return ""

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

        st.subheader("IAM User Visibility")

        iam_users = get_iam_users()

        if iam_users:
            iam_df = pd.DataFrame(iam_users)

            st.dataframe(
                iam_df,
                use_container_width=True
            )
        else:
            st.warning("No IAM users found.")

        st.subheader("AI Security Risk Analysis")

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

    else:
        st.warning("No EC2 instances found.")