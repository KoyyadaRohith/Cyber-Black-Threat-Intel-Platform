import requests
import hashlib
import random
from config import Config

def check_ip_virustotal(ip, api_key=None):
    """
    Query VirusTotal v3 IP Address API with User-Agent header.
    If an API key is present but a request error or status error occurs, logs details and returns clean empty live metrics.
    If no API key is present at all, falls back to mock data.
    """
    key = api_key or Config.VIRUSTOTAL_API_KEY
    
    if key and key.strip():
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        headers = {
            'x-apikey': key,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                attributes = response.json().get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                votes = attributes.get('reputation', 0)
                
                # Extract malicious detections and security vendors
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                tags = attributes.get('tags', [])
                asn = attributes.get('asn', 0)
                network = attributes.get('network', '')
                
                print(f"[API LOG] VirusTotal response status 200 for {ip}. Detections: {malicious}/{total}")
                return {
                    'ip': ip,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'harmless_count': harmless,
                    'undetected_count': undetected,
                    'total_engines': total or 90,
                    'reputation_score': votes,
                    'tags': tags[:5],
                    'network': network,
                    'asn': asn,
                    'is_mock': False
                }
            else:
                print(f"[API ERROR] VirusTotal responded with status {response.status_code}: {response.text}")
                return {
                    'ip': ip,
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'harmless_count': 0,
                    'undetected_count': 0,
                    'total_engines': 90,
                    'reputation_score': 0,
                    'tags': [],
                    'network': '',
                    'asn': 0,
                    'is_mock': False,
                    'api_error': f"HTTP {response.status_code}"
                }
        except Exception as e:
            print(f"[API ERROR] VirusTotal request failed: {e}")
            return {
                'ip': ip,
                'malicious_count': 0,
                'suspicious_count': 0,
                'harmless_count': 0,
                'undetected_count': 0,
                'total_engines': 90,
                'reputation_score': 0,
                'tags': [],
                'network': '',
                'asn': 0,
                'is_mock': False,
                'api_error': str(e)
            }
            
    # Mock fallback when no key is configured
    return get_mock_virustotal_data(ip)

def get_mock_virustotal_data(ip):
    """Generates realistic mock VT data seeded by the IP hash for consistency."""
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    random.seed(ip_hash)
    
    # Calculate mock risk category deterministically
    risk_factor = ip_hash % 100
    
    total_engines = 89
    if risk_factor < 50: # Safe
        malicious = 0
        suspicious = 0
        harmless = random.randint(70, 80)
        undetected = total_engines - harmless
        reputation = random.randint(0, 10)
        tags = []
    elif risk_factor < 80: # Suspicious
        malicious = random.randint(1, 8)
        suspicious = random.randint(1, 4)
        harmless = random.randint(50, 65)
        undetected = total_engines - harmless - malicious - suspicious
        reputation = -random.randint(5, 25)
        tags = random.sample(["vpn", "crawler", "ssh-scan", "hosting"], random.randint(1, 2))
    else: # Malicious
        malicious = random.randint(15, 62)
        suspicious = random.randint(2, 8)
        harmless = random.randint(10, 25)
        undetected = total_engines - harmless - malicious - suspicious
        reputation = -random.randint(40, 180)
        tags = random.sample(["botnet", "malware-distribution", "phishing", "brute-force", "ddos", "c2"], random.randint(2, 4))
        
    # Map network and ASN based on risk level
    asns = [13335, 16509, 14061, 24940, 32244, 4134, 4837]
    asn = random.choice(asns)
    network = f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0/16"

    return {
        'ip': ip,
        'malicious_count': malicious,
        'suspicious_count': suspicious,
        'harmless_count': harmless,
        'undetected_count': undetected,
        'total_engines': total_engines,
        'reputation_score': reputation,
        'tags': tags,
        'network': network,
        'asn': asn,
        'is_mock': True
    }
