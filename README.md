# 🛡️ Automated Log Security Analyzer

A lightweight Python-based Log Security Analyzer designed to parse server log files, detect potential cyber security threats (such as Brute Force attempts, Unauthorized Access, SQL Injection, DDoS, and System Errors), summarize log metrics, and generate automated security reporting.

---

## 🚀 Features

- **Log Parsing:** Extracts Timestamps, Status Levels (`INFO`, `WARN`, `ERROR`), and Event Messages using Regular Expressions (`re`).
- **Threat Detection & Filtering:** Isolates critical security events and warnings (`ERROR` & `WARN`) for fast incident response.
- **Log Summary Counter:** Provides an aggregated count of log types using `pandas`.
- **Automated Reporting:** Exports cleanly formatted security audit reports directly to a text file (`security_report.txt`).

---

## 🛠️ Tech Stack & Requirements

- **Language:** Python 3.x
- **Libraries:**
  - `pandas` (Data Analysis & Manipulation)
  - `re` (Regex for Pattern Matching)

---

## 📂 Project Structure

```text
security-analyzer/
├── main.py              # Main Python script for parsing and analyzing logs
├── server.log           # Raw sample server logs containing multi-day security events
├── security_report.txt  # Auto-generated security analysis report
└── README.md            # Project documentation
