import re
import pandas as pd

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

df = analyze_logs_from_file('server.log')
print(df) 
26-08-01 10:00:01 - INFO - Authentication success for user admin from IP 192.168.1.5",
    "2026-08-01 10:05:22 - ERROR - Failed login attempt for user root from IP 203.0.113.45 - Invalid credentials",
    "2026-08-01 10:12:45 - INFO - Password policy updated by admin",
    "2026-08-01 11:30:10 - WARN - Unusual access pattern detected for user johndoe from IP 198.51.100.22",
    "2026-08-01 12:45:33 - INFO - User johndoe logged out",
    "2026-08-01 13:02:11 - ERROR - Unauthorized access attempt to /admin directory from IP 203.0.113.88",
    "2026-08-01 14:15:20 - INFO - System backup completed successfully",
    "2026-08-01 15:22:40 - ERROR - Failed login attempt for user guest from IP 192.168.1.100 - Account locked",
    "2026-08-01 16:00:15 - INFO - Database optimization started",
    "2026-08-01 16:45:00 - INFO - Database optimization completed",
    "2026-08-01 17:10:05 - WARN - High memory usage detected on server node 3",
    "2026-08-01 18:00:00 - INFO - Scheduled maintenance window opened",
    "2026-08-01 19:30:00 - INFO - Scheduled maintenance window closed",
    "2026-08-01 20:05:12 - ERROR - Critical - SSL certificate expired on web-server-1",
    "2026-08-01 21:15:30 - INFO - SSL certificate renewed and applied",
    "2026-08-01 22:00:00 - INFO - Daily security scan initiated",
    "2026-08-01 22:30:45 - INFO - Daily security scan completed with zero threats found",
    "2026-08-01 23:55:00 - INFO - System status check - Normal"
]
def analyze_logs(logs):
    parsed_logs = []
    for log in logs:
        match = re.match(r'(.*?) - (.*)', log)
        if match:
            timestamp, message = match.groups()
            parsed_logs.append({'TIMESTAMP': timestamp, 'MESSAGE': message})
    return pd.DataFrame(parsed_logs)

df = analyze_logs(log_data)
print(df)
