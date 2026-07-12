def calculate_risk_score(abuse_data, vt_data, whois_data):
    """
    Calculate an aggregate threat intelligence risk score (0-100)
    based on AbuseIPDB, VirusTotal, and WHOIS findings.
    """
    # 1. Abuse Confidence Score weight: 50%
    # AbuseIPDB abuse_score ranges from 0 to 100
    abuse_score = abuse_data.get('abuse_score', 0)
    weighted_abuse = abuse_score * 0.50
    
    # 2. VirusTotal malicious detections weight: 35%
    # VT ratio: malicious / total engines. If engines is 0, defaults to 0.
    vt_malicious = vt_data.get('malicious_count', 0)
    vt_total = vt_data.get('total_engines', 89)
    vt_ratio_score = 0
    if vt_total > 0:
        vt_ratio_score = (vt_malicious / vt_total) * 100
    
    # Cap VT score weight
    weighted_vt = min(vt_ratio_score * 0.35, 35)
    
    # 3. WHOIS & Hosting Profile weight: 15%
    # Deduct points if it's hosted in known VPN/datacenter ranges with dark reputation
    weighted_whois = 0
    usage_type = abuse_data.get('usage_type', '').lower()
    
    # Hosting providers/Data centers have higher susceptibility to spam/abuse bots
    if 'data center' in usage_type or 'hosting' in usage_type:
        weighted_whois += 8
    
    # Check VT tags for proxy/vpn indicators
    vt_tags = [t.lower() for t in vt_data.get('tags', [])]
    if any(tag in vt_tags for tag in ['vpn', 'proxy', 'tor', 'anonymous']):
        weighted_whois += 7
        
    # Aggregate total score
    total_score = round(weighted_abuse + weighted_vt + weighted_whois)
    
    # Bound final score between 0 and 100
    final_score = max(0, min(100, total_score))
    
    # Classification logic (5 levels for CBTIP V4.0):
    # 0 - 20: Safe
    # 21 - 40: Low Risk
    # 41 - 60: Suspicious
    # 61 - 80: High Risk
    # 81 - 100: Malicious
    if final_score <= 20:
        classification = "Safe"
    elif final_score <= 40:
        classification = "Low Risk"
    elif final_score <= 60:
        classification = "Suspicious"
    elif final_score <= 80:
        classification = "High Risk"
    else:
        classification = "Malicious"
        
    print(f"[SCORING LOG] IP: {abuse_data.get('ip', 'Unknown')} | "
          f"Abuse score: {abuse_score}% (contrib: {round(weighted_abuse, 1)}) | "
          f"VT malicious: {vt_malicious}/{vt_total} (contrib: {round(weighted_vt, 1)}) | "
          f"WHOIS Profile: {weighted_whois} (contrib: {round(weighted_whois, 1)}) | "
          f"Total Score: {final_score}/100 | Class: {classification}")
        
    return {
        'score': final_score,
        'classification': classification,
        'breakdown': {
            'abuse_contribution': round(weighted_abuse, 1),
            'vt_contribution': round(weighted_vt, 1),
            'profile_contribution': round(weighted_whois, 1)
        }
    }
