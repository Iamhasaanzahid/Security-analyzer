import re
import pandas as pd

# Pandas Output Settings
pd.set_option('display.max_rows', None)
pd.set_option('display.max_colwidth', None)

def analyze_logs_from_file(file_path):
    parsed_logs = []
    
    with open(file_path, 'r') as file:
        logs = file.readlines()
        
    for log in logs:
        match = re.match(r'(.*?)\s+-\s+(.*?)\s+-\s+(.*)', log.strip())
        if match:
            timestamp, status, message = match.groups()
            parsed_logs.append({
                'TIMESTAMP': timestamp,
                'STATUS': status,
                'MESSAGE': message
            })
            
    return pd.DataFrame(parsed_logs)

def filter_security_alerts(df):
    alerts = df[df['STATUS'].isin(['ERROR', 'WARN'])]
    return alerts

def generate_log_summary(df):
    summary = df['STATUS'].value_counts()
    return summary

def save_report_to_file(summary, alerts_df, output_file='security_report.txt'):
    with open(output_file, 'w') as file:
        file.write("=========================================\n")
        file.write("        SECURITY ANALYSIS REPORT         \n")
        file.write("=========================================\n\n")
        
        file.write("=== LOGS SUMMARY COUNTER ===\n")
        file.write(summary.to_string())
        file.write("\n\n" + "="*41 + "\n\n")
        
        file.write("=== SECURITY ALERTS & ERRORS ONLY ===\n")
        file.write(alerts_df.to_string())
        file.write("\n")

# 1. Read and Analyze Logs
df = analyze_logs_from_file('server.log')

# 2. Process Summary & Alerts
summary = generate_log_summary(df)
alerts_df = filter_security_alerts(df)

# 3. Print Output to Terminal
print("=== LOGS SUMMARY COUNTER ===")
print(summary)
print("\n" + "="*35 + "\n")

print("=== SECURITY ALERTS & ERRORS ONLY ===")
print(alerts_df)

# 4. Save Report to File
save_report_to_file(summary, alerts_df)
print("\n[+] Report saved successfully to 'security_report.txt'")
