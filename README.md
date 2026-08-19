# 🛡️ Automated Log Security & Threat Analyzer

A high-performance Python-based Log Security Analyzer designed for SOC Analysts and Security Engineers. It parses raw server log files, extracts IP addresses, identifies critical threat patterns, generates statistical log summaries, and exports comprehensive security reports alongside visual metrics.

## 🔑 Key Features
- **Log Parsing & Regex Matching:** Extracts Timestamps, Status Levels, IP Addresses, and Event Messages using Regular Expressions.
- **Brute Force & Threat Detection:** Tracks suspicious IP addresses making repeated failed attempts and triggers thresholds for Brute Force identification.
- **Visual Data Analytics:** Automatically generates a color-coded bar chart visualizing log event distributions.
- **Incident Filtering:** Isolates critical security events for accelerated incident response.
- **Automated Security Reporting:** Saves neatly formatted security audit summaries directly into a report file.
- **Secure Authentication System:** Implements user registration with email verification, secure password hashing using bcrypt, and a login functionality to verify credentials.

## 🛠️ Tech Stack & Requirements
- **Language:** Python 3.x
- **Libraries:**
  - `streamlit` (Interactive Dashboard & UI)
  - `pandas` (Data Processing & Structuring)
  - `matplotlib` (Data Visualization & Charting)
  - `requests` (API interactions & Web Requests)
  - `bcrypt` (Secure Password Hashing)
  - `re` (Regular Expression Pattern Matching)

## 📁 Project Structure
```text
security-analyzer/
├── .devcontainer/        # Dev Container configuration
├── auth_system.py        # Authentication & User Management module
├── block_ips.py          # IP Blocking and Threat Detection logic
├── main.py               # Main Python engine (Parser, Threat Detector & Streamlit UI)
├── notifications.py      # Alerting and Notification system
├── requirements.txt      # Project dependencies and libraries
├── server.log            # Raw server log dataset
├── security_report.txt   # Auto-generated security report
├── log_summary_chart.png # Auto-generated visual metrics chart
└── README.md             # Comprehensive project documentation
