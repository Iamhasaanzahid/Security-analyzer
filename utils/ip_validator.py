import ipaddress

def is_valid_ip(ip_str: str) -> bool:
    """
    Check if the input string is a valid IPv4 or IPv6 address.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def is_public_ip(ip_str: str) -> bool:
    """
    Check if the IP is globally routable (Public).
    Returns False for RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
    loopback (127.0.0.1), link-local, multicast, and invalid IPs.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        # is_global automatically filters out private (RFC 1918), loopback, reserved, and link-local IPs
        return ip_obj.is_global
    except ValueError:
        return False
