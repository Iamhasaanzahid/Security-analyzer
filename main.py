import re
import pandas as pd
import matplotlib.pyplot as plt
import streamlit as st

# Streamlit Page Setup
st.set_page_config(page_title="Security Log & Threat Analyzer", layout="wide", page_icon="🛡️")

# Title and Description
st.title("🛡️ Security Log & Threat Analyzer Dashboard")
st.markdown("Upload your server log files below to analyze security events, detect brute-force attempts, and generate visual threat intelligence.")

# --- CORE LOGIC FUNCTIONS ---
def parse_logs_from_content(log_lines):
    parsed_logs = []
    for log in log_lines:
        if not log.strip():
            continue
            
        # Flexible Regex Matching
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
    # Detect ERROR, WARN, and FAILED status logs
    return df[df['STATUS'].isin(['ERROR', 'WARN', 'FAILED LOGIN', 'FAILED'])]

def generate_log_summary(df):
    return df['STATUS'].value_counts()

def detect_brute_force(df):
    # Detect Brute Force on ERROR or FAILED LOGIN
    failed_df = df[df['STATUS'].isin(['ERROR', 'FAILED LOGIN', 'FAILED'])]
    ip_counts = failed_df['IP_ADDRESS'].value_counts()
    
    # Filter out N/A IPs and detect IPs with 2 or more failed attempts
    ip_counts = ip_counts[ip_counts.index != 'N/A']
    suspicious_ips = ip_counts[ip_counts >= 2]
    return suspicious_ips

# --- STREAMLIT UI LAYOUT ---

# File Upload Sidebar
st.sidebar.header("📂 Upload Log File")
uploaded_file = st.sidebar.file_uploader("Choose a .log or .txt file", type=["log", "txt"])

if uploaded_file is not None:
    # Read uploaded file
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
            
            # Dynamic colors for chart
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
            st.subheader("🚨 Brute Force Detection")
            if not brute_force_ips.empty:
                st.error("🚨 Warning: Multiple Failed Logins / Errors Detected!")
                bf_df = brute_force_ips.reset_index()
                bf_df.columns = ['IP Address', 'Failed Attempts']
                st.dataframe(bf_df, use_container_width=True)
            else:
                st.success("No suspicious Brute Force activity detected.")

        st.markdown("---")

        # Detailed Security Alerts Table
        st.subheader("⚠️ Security Alerts & Error Logs")
        if not alerts_df.empty:
            st.dataframe(alerts_df, use_container_width=True)
        else:
            st.info("No ERROR, WARN or FAILED status logs found.")

        # Complete Parsed Logs View
        with st.expander("🔍 View Full Parsed Log Data"):
            st.dataframe(df, use_container_width=True)

    else:
        st.warning("Could not parse any valid logs. Please check the log file format.")

else:
    st.info("👆 Please upload a `server.log` file using the sidebar to run the security analysis.")
