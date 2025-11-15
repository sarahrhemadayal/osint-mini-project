import requests

def get_public_ip():
    """Return the user's public IP address or None on error."""
    try:
        res = requests.get('https://api.ipify.org?format=json', timeout=4)
        if res.status_code == 200:
            return res.json().get('ip')
    except Exception:
        return None

# Usage:
# from find_ip import get_public_ip
# ip = get_public_ip()
