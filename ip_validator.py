import ipaddress

def is_valid_ip(ip_str):
    """
    Check if the input string is a valid IPv4 or IPv6 address.
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def is_public_ip(ip_str):
    """
    Check if the IP is globally routable (Public).
    Returns False for RFC 1918 private ranges (10.x, 172.16.x-172.31.x, 192.168.x),
    loopback (127.0.0.1), and invalid IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_global
    except ValueError:
        return False
