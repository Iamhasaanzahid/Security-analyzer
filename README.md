# 🛡️ Automated Log Security & Threat Analyzer

A high-performance Python-based Log Security Analyzer designed for SOC Analysts and Security Engineers. It parses raw server log files, extracts IP addresses, identifies critical threat patterns (such as Brute Force attempts and Unauthorized Access), generates statistical log summaries, and exports comprehensive security reports alongside visual metrics.

---

## 🚀 Key Features

- **Log Parsing & Regex Matching:** Extracts Timestamps, Status Levels (`INFO`, `WARN`, `ERROR`), IP Addresses, and Event Messages using Regular Expressions (`re`).
- **Brute Force & Threat Detection:** Tracks suspicious IP addresses making repeated failed attempts and triggers thresholds for Brute Force identification.
- **Visual Data Analytics:** Automatically generates a color-coded bar chart (`log_summary_chart.png`) visualizing log event distributions.
- **Incident Filtering:** Isolates critical security events (`ERROR` & `WARN`) for accelerated incident response.
- **Automated Security Reporting:** Saves neatly formatted security audit summaries directly into `security_report.txt`.

---

## 🛠️ Tech Stack & Requirements

- **Language:** Python 3.x
- **Libraries:**
  - `pandas` (Data Processing & Structuring)
  - `matplotlib` (Data Visualization & Charting)
  - `re` (Regular Expression Pattern Matching)

---

## 📂 Project Structure

```text
security-analyzer/
├── main.py                 # Main Python engine (Parser, Threat Detector & Reporter)
├── server.log              # Raw server log dataset
├── security_report.txt     # Auto-generated security report
├── log_summary_chart.png   # Auto-generated visual metrics chart
└── README.md               # Comprehensive project documentation
