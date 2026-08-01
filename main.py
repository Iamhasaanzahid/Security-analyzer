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
