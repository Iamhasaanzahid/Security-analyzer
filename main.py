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

df = analyze_logs_from_file('server.log')
alerts_df = filter_security_alerts(df)

print("=== SECURITY ALERTS & ERRORS ONLY ===")
print(alerts_df)
