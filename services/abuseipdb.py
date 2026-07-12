import requests
import hashlib
import random
from config import Config

def check_ip_abuse(ip, api_key=None):
    """
    Query AbuseIPDB API to check the reputation of an IP address.
    If an API key is present but a request error or status error occurs, logs details and returns clean empty live metrics.
    If no API key is present at all, falls back to mock data.
    """
    key = api_key or Config.ABUSEIPDB_API_KEY
    
    if key and key.strip():
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': key
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json().get('data', {})
                print(f"[API LOG] AbuseIPDB response status 200 for {ip}. Reports: {data.get('totalReports', 0)}, Score: {data.get('abuseConfidenceScore', 0)}%")
                return {
                    'ip': ip,
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported_at': data.get('lastReportedAt'),
                    'country_code': data.get('countryCode', 'US'),
                    'country_name': data.get('countryName', 'United States'),
                    'isp': data.get('isp', 'Unknown ISP'),
                    'domain': data.get('domain', ''),
                    'usage_type': data.get('usageType', 'Commercial'),
                    'is_mock': False
                }
            else:
                print(f"[API ERROR] AbuseIPDB responded with status {response.status_code}: {response.text}")
                return {
                    'ip': ip,
                    'abuse_score': 0,
                    'total_reports': 0,
                    'last_reported_at': None,
                    'country_code': 'US',
                    'country_name': 'United States',
                    'isp': 'Unknown ISP (API Error)',
                    'domain': '',
                    'usage_type': 'Unknown',
                    'is_mock': False,
                    'api_error': f"HTTP {response.status_code}"
                }
        except Exception as e:
            print(f"[API ERROR] AbuseIPDB request failed: {e}")
            return {
                'ip': ip,
                'abuse_score': 0,
                'total_reports': 0,
                'last_reported_at': None,
                'country_code': 'US',
                'country_name': 'United States',
                'isp': 'Unknown ISP (Connection Error)',
                'domain': '',
                'usage_type': 'Unknown',
                'is_mock': False,
                'api_error': str(e)
            }
            
    # Mock fallback (deterministic based on IP) when no key is configured
    return get_mock_abuse_data(ip)

def get_mock_abuse_data(ip):
    """Generates realistic mock data seeded by the IP hash for consistency."""
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    random.seed(ip_hash)
    
    # Standard security assets
    isps = [
        "Amazon Web Services, Inc.", "DigitalOcean, LLC", "Cloudflare, Inc.", 
        "Google LLC", "Comcast Cable Communications, LLC", "Microsoft Corporation", 
        "OVH SAS", "Chinastart Telecommunications", "Shenzhen Tencent Computer Systems"
    ]
    countries = [
        ("US", "United States"), ("CN", "China"), ("NL", "Netherlands"), 
        ("DE", "Germany"), ("RU", "Russia"), ("GB", "United Kingdom"), 
        ("FR", "France"), ("IN", "India"), ("BR", "Brazil")
    ]
    usage_types = ["Data Center/Web Hosting/Transit", "Commercial", "Fixed Line ISP", "Mobile ISP"]
    
    # Calculate mock risk category deterministically
    # Some ranges of IPs will be high risk, others low risk
    risk_factor = ip_hash % 100
    
    if risk_factor < 50: # Safe IP (50% probability)
        abuse_score = random.randint(0, 5)
        total_reports = 0
        last_reported_at = None
        isp = random.choice(["Google LLC", "Cloudflare, Inc.", "Amazon Web Services, Inc."])
        country = ("US", "United States")
        usage_type = "Commercial"
    elif risk_factor < 80: # Suspicious IP (30% probability)
        abuse_score = random.randint(15, 55)
        total_reports = random.randint(3, 25)
        last_reported_at = "2026-06-02T11:45:00Z"
        isp = random.choice(isps)
        country = random.choice(countries)
        usage_type = random.choice(usage_types)
    else: # Malicious IP (20% probability)
        abuse_score = random.randint(65, 100)
        total_reports = random.randint(50, 480)
        last_reported_at = "2026-06-03T08:12:30Z"
        isp = random.choice(["OVH SAS", "Chinastart Telecommunications", "Shenzhen Tencent Computer Systems", "DigitalOcean, LLC"])
        country = random.choice([("CN", "China"), ("RU", "Russia"), ("NL", "Netherlands"), ("US", "United States")])
        usage_type = "Data Center/Web Hosting/Transit"

    return {
        'ip': ip,
        'abuse_score': abuse_score,
        'total_reports': total_reports,
        'last_reported_at': last_reported_at,
        'country_code': country[0],
        'country_name': country[1],
        'isp': isp,
        'domain': isp.split(',')[0].lower().replace(' ', '') + '.com',
        'usage_type': usage_type,
        'is_mock': True
    }
