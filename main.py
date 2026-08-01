```python
import re
import pandas as pd

log_data = [
    "2026-08-01 10:00:01 - Authentication success for user admin",
    "2026-08-01 10:05:22 - Failed login attempt for user root",
    "2026-08-01 10:12:45 - Password policy updated by admin"
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

```
