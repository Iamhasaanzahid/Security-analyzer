import re
import pandas as pd
import matplotlib.pyplot as plt

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
            
            ip_match = re.search(r'IP\s+([0-9\.]+)', message)
            ip_address = ip_match.group(1) if ip_match else "N/A"
            
            parsed_logs.append({
                'TIMESTAMP': timestamp,
                'STATUS': status,
                'IP_ADDRESS': ip_address,
                'MESSAGE': message
            })
            
    return pd.DataFrame(parsed_logs)

def filter_security_alerts(df):
    alerts = df[df['STATUS'].isin(['ERROR', 'WARN'])]
    return alerts

def generate_log_summary(df):
    summary = df['STATUS'].value_counts()
    return summary

def detect_brute_force(df):
    errors_df = df[df['STATUS'] == 'ERROR']
    ip_counts = errors_df['IP_ADDRESS'].value_counts()
    suspicious_ips = ip_counts[ip_counts >= 2]
    return suspicious_ips

def save_advanced_report(summary, alerts_df, brute_force_ips, output_file='security_report.txt'):
    with open(output_file, 'w') as file:
        file.write("=========================================\n")
        file.write("      ADVANCED SECURITY AUDIT REPORT     \n")
        file.write("=========================================\n\n")
        
        file.write("=== LOGS SUMMARY COUNTER ===\n")
        file.write(summary.to_string())
        file.write("\n\n" + "="*41 + "\n\n")
        
        file.write("=== SUSPICIOUS IPS / BRUTE FORCE DETECTED ===\n")
        if not brute_force_ips.empty:
            file.write(brute_force_ips.to_string())
        else:
            file.write("No Brute Force activity detected.")
        file.write("\n\n" + "="*41 + "\n\n")
        
        file.write("=== SECURITY ALERTS & ERRORS ONLY ===\n")
        file.write(alerts_df.to_string())
        file.write("\n")

def generate_log_chart(summary, chart_file='log_summary_chart.png'):
    plt.figure(figsize=(8, 5))
    colors = ['#2ecc71' if x == 'INFO' else '#f39c12' if x == 'WARN' else '#e74c3c' for x in summary.index]
    
    plt.bar(summary.index, summary.values, color=colors)
    plt.title('Log Status Distribution Summary', fontsize=14, fontweight='bold')
    plt.xlabel('Log Level Status', fontsize=12)
    plt.ylabel('Event Count', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    for i, value in enumerate(summary.values):
        plt.text(i, value + 0.5, str(value), ha='center', fontweight='bold')
        
    plt.tight_layout()
    plt.savefig(chart_file)
    plt.close()

# --- MAIN EXECUTION ---
df = analyze_logs_from_file('server.log')

summary = generate_log_summary(df)
alerts_df = filter_security_alerts(df)
brute_force_ips = detect_brute_force(df)

print("=== LOGS SUMMARY COUNTER ===")
print(summary)
print("\n" + "="*35 + "\n")

print("=== SUSPICIOUS IPS & POSSIBLE BRUTE FORCE ===")
if not brute_force_ips.empty:
    print(brute_force_ips)
else:
    print("No suspicious IP patterns found.")
print("\n" + "="*35 + "\n")

print("=== SECURITY ALERTS & ERRORS ONLY ===")
print(alerts_df)

save_advanced_report(summary, alerts_df, brute_force_ips)
generate_log_chart(summary)

print("\n[+] Advanced Security Report saved to 'security_report.txt'")
print("[+] Log Summary Chart generated and saved to 'log_summary_chart.png'")
