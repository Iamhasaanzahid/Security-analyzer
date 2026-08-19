# block_ips.py

failed_attempts = {}
blocked_ips = set()
THRESHOLD = 5  # फेल होने की सीमा


def track_failed_attempt(ip_address):
    attempts = failed_attempts.get(ip_address, 0) + 1
    failed_attempts[ip_address] = attempts

    if attempts >= THRESHOLD:
        blocked_ips.add(ip_address)
        print(f"IP Blocked: {ip_address}")
        return True
    return False


def is_ip_blocked(ip_address):
    return ip_address in blocked_ips
