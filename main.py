import sys
from pathlib import Path
import re
import requests
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# Project root path ko system path mein add karein taake subfolders access ho sakein
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

# Do alag alag folders se direct import (Apne folder names ke mutabiq adjust karein agar mukhtalif hon)
try:
    from threat_intel_dir.threat_intel import check_ip_reputation
except ModuleNotFoundError:
    try:
        from threat_intel.threat_intel import check_ip_reputation
    except ModuleNotFoundError:
        from threat_intel import check_ip_reputation

# Streamlit Page Setup
st.set_page_config(page_title="Security Log & Threat Analyzer", layout="wide", page_icon="🛡️")

# Title and Description
st.title("🛡️ Security Log & Threat Analyzer Dashboard")
st.markdown("Upload your server log files below to analyze security events, detect brute-force attempts, and generate visual threat intelligence.")

# --- CORE LOGIC FUNCTIONS ---

@st.cache_data(ttl=3600)
def get_ip_location_details(ip):
    """Fetch country, city, and ISP for public IPs using IP-API."""
    intel = check_ip_reputation(ip)
    if not intel.get("is_public"):
        return "Local/Private IP", "Local", "Internal Network"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp", timeout=3)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country', 'Unknown')
            city = data.get('city', 'Unknown')
            isp = data.get('isp', 'Unknown')
            return country, city, isp
    except Exception:
        pass
    return "Unknown", "Unknown", "Unknown"

def parse_logs_from_content(log_lines):
    parsed_logs = []
    for log in log_lines:
        if not log.strip():
            continue
            
        match = re.match(r'(.*?)\s+-\s+(.*?)\s+-\s+(.*)', log.strip())
        if match:
            timestamp, status, message = match.groups()
            ip_match = re.search(r'IP\s+([0-9\.]+)', message)
            ip_address = ip_match.group(1) if ip_match else "N/A"
            
            parsed_logs.append({
                'TIMESTAMP': timestamp.strip(),
                'STATUS': status.strip().upper(),
                'IP_ADDRESS': ip_address,
                'MESSAGE': message.strip()
            })
    return pd.DataFrame(parsed_logs)

def filter_security_alerts(df):
    return df[df['STATUS'].isin(['ERROR', 'WARN', 'FAILED LOGIN', 'FAILED'])]

def generate_log_summary(df):
    return df['STATUS'].value_counts()

def detect_brute_force(df):
    failed_df = df[df['STATUS'].isin(['ERROR', 'FAILED LOGIN', 'FAILED'])]
    ip_counts = failed_df['IP_ADDRESS'].value_counts()
    
    ip_counts = ip_counts[ip_counts.index != 'N/A']
    suspicious_ips = ip_counts[ip_counts >= 2]
    
    if not suspicious_ips.empty:
        bf_df = suspicious_ips.reset_index()
        bf_df.columns = ['IP Address', 'Failed Attempts']
        
        # 1. Location Data Fetch
        location_data = bf_df['IP Address'].apply(get_ip_location_details)
        bf_df['Country'] = [loc[0] for loc in location_data]
        bf_df['City'] = [loc[1] for loc in location_data]
        bf_df['ISP / Host'] = [loc[2] for loc in location_data]
        
        # 2. Threat Intel & AbuseIPDB Score Enrichment
        intel_data = bf_df['IP Address'].apply(check_ip_reputation)
        bf_df['Abuse Score (%)'] = [f"{item.get('abuse_score', 0)}%" for item in intel_data]
        bf_df['Abuse Reports'] = [item.get('reports', 0) for item in intel_data]
        bf_df['IP Type'] = ["Public" if item.get('is_public') else "Private (RFC 1918)" for item in intel_data]
        
        return bf_df
        
    return pd.DataFrame()

# Helper function to convert DataFrames to CSV
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# --- STREAMLIT UI LAYOUT ---

# File Upload Sidebar
st.sidebar.header("📂 Upload Log File")
uploaded_file = st.sidebar.file_uploader("Choose a .log or .txt file", type=["log", "txt"])

if uploaded_file is not None:
    file_contents = uploaded_file.getvalue().decode("utf-8").splitlines()
    df = parse_logs_from_content(file_contents)

    if not df.empty:
        summary = generate_log_summary(df)
        alerts_df = filter_security_alerts(df)
        brute_force_ips = detect_brute_force(df)

        # Top Metrics Section
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Events Logged", len(df))
        col2.metric("Security Alerts (ERROR/WARN/FAILED)", len(alerts_df))
        col3.metric("Suspicious IPs Detected", len(brute_force_ips))

        st.markdown("---")

        # Two Column Layout for Chart and Brute Force Detection
        left_col, right_col = st.columns([1, 1])

        with left_col:
            st.subheader("📊 Log Status Distribution")
            fig, ax = plt.subplots(figsize=(6, 4))
            
            colors = []
            for status in summary.index:
                if status in ['ERROR', 'FAILED LOGIN', 'FAILED']:
                    colors.append('#e74c3c') # Red
                elif status == 'WARN':
                    colors.append('#f39c12') # Orange
                else:
                    colors.append('#2ecc71') # Green
                    
            ax.bar(summary.index, summary.values, color=colors)
            ax.set_title('Log Status Summary', fontsize=12, fontweight='bold')
            ax.set_ylabel('Event Count')
            ax.grid(axis='y', linestyle='--', alpha=0.7)
            
            for i, value in enumerate(summary.values):
                ax.text(i, value + 0.1, str(value), ha='center', fontweight='bold')
                
            st.pyplot(fig)

        with right_col:
            st.subheader("🚨 Brute Force & Threat Intelligence")
            if not brute_force_ips.empty:
                st.error("🚨 Warning: Suspicious Activity Detected!")
                st.dataframe(brute_force_ips, use_container_width=True)
                
                # High Threat Alert if Abuse Score >= 50%
                for _, row in brute_force_ips.iterrows():
                    try:
                        score_num = int(str(row['Abuse Score (%)']).replace('%', ''))
                        if score_num >= 50:
                            st.warning(f"⚠️ High-Risk IP Flagged: **{row['IP Address']}** (Abuse Confidence: {row['Abuse Score (%)']})")
                    except ValueError:
                        pass

                # Download CSV Button for Brute Force Threat Report
                bf_csv = convert_df_to_csv(brute_force_ips)
                st.download_button(
                    label="📥 Download Threat Report (CSV)",
                    data=bf_csv,
                    file_name="brute_force_threats.csv",
                    mime="text/csv"
                )
            else:
                st.success("No suspicious Brute Force activity detected.")

        st.markdown("---")

        # Detailed Security Alerts Table
        st.subheader("⚠️ Security Alerts & Error Logs")
        if not alerts_df.empty:
            st.dataframe(alerts_df, use_container_width=True)
            
            # Download CSV Button for Security Alerts
            alerts_csv = convert_df_to_csv(alerts_df)
            st.download_button(
                label="📥 Download All Security Alerts (CSV)",
                data=alerts_csv,
                file_name="security_alerts_report.csv",
                mime="text/csv"
            )
        else:
            st.info("No ERROR, WARN or FAILED status logs found.")

        # Complete Parsed Logs View
        with st.expander("🔍 View Full Parsed Log Data"):
            st.dataframe(df, use_container_width=True)
            
            # Download CSV Button for Full Log Data
            full_csv = convert_df_to_csv(df)
            st.download_button(
                label="📥 Download Full Parsed Log Data (CSV)",
                data=full_csv,
                file_name="full_parsed_logs.csv",
                mime="text/csv"
            )

    else:
        st.warning("Could not parse any valid logs. Please check the log file format.")

else:
    st.info("👆 Please upload a `server.log` file using the sidebar to run the security analysis.")
