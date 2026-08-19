import requests
from ip_validator import is_public_ip

# API Key variable (Aap Streamlit secrets ya environment variable se bhi le sakte hain)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"

def check_ip_reputation(ip_str):
    """
    Query AbuseIPDB API v2 for threat intelligence on a given IP address.
    """
    ip_clean = str(ip_str).strip()
    
    # Step 1: Filter out Private/RFC1918/Local IPs
    if not is_public_ip(ip_clean):
        return {
            "status": "Skipped",
            "is_public": False,
            "abuse_score": 0,
            "reports": 0,
            "country": "Local/Private",
            "isp": "Internal Network",
            "message": "Private IP (RFC 1918) - No threat lookup required."
        }

    # Step 2: Query AbuseIPDB for Public IP
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_clean,
        "maxAgeInDays": "90",
        "verbose": ""
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "status": "Success",
                "is_public": True,
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "domain": data.get("domain", "N/A"),
                "message": "Lookup successful"
            }
        else:
            return {
                "status": "Error",
                "is_public": True,
                "abuse_score": 0,
                "reports": 0,
                "country": "N/A",
                "isp": "N/A",
                "message": f"API Error: HTTP {response.status_code}"
            }
            
    except requests.RequestException as e:
        return {
            "status": "Error",
            "is_public": True,
            "abuse_score": 0,
            "reports": 0,
            "country": "N/A",
            "isp": "N/A",
            "message": f"Connection failed: {str(e)}"
        }
