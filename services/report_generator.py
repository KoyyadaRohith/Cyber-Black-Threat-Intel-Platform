import io
import csv
from datetime import datetime

def generate_csv_report(data_list, fieldnames=None):
    """
    Generate a CSV formatted string from a list of dictionaries.
    If fieldnames is not provided, dynamically generate headers from the dictionary keys.
    """
    if not data_list:
        return ""
        
    if not fieldnames:
        # Dynamically extract all unique keys from data_list
        keys = set()
        for row in data_list:
            keys.update(row.keys())
        fieldnames = sorted(list(keys))
        
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for row in data_list:
        writer.writerow(row)
    return output.getvalue()

def generate_txt_individual(details):
    """
    Generate a professional security audit text report for a single IP.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report = []
    report.append("======================================================================")
    report.append("          CYBER BLACK THREAT INTEL PLATFORM - SECURITY AUDIT REPORT")
    report.append("======================================================================")
    report.append(f"Report Timestamp: {timestamp}")
    report.append(f"Target IP Address: {details['ip']}")
    report.append("----------------------------------------------------------------------")
    report.append("SUMMARY DIAGNOSIS")
    report.append("----------------------------------------------------------------------")
    report.append(f"Threat Score:     {details['risk']['score']}/100")
    report.append(f"Classification:   {details['risk']['classification'].upper()}")
    report.append("\nAnalyst Findings Summary:")
    report.append(details['summary'])
    report.append("----------------------------------------------------------------------")
    report.append("INFRASTRUCTURE PROFILE")
    report.append("----------------------------------------------------------------------")
    report.append(f"ISP Network:      {details['whois']['isp']}")
    report.append(f"ASN Network ID:   {details['whois']['asn']} ({details['whois']['asn_org']})")
    report.append(f"Autonomous Org:   {details['whois']['org']}")
    report.append(f"Target Location:  {details['whois']['city']}, {details['whois']['region']}, {details['whois']['country']}")
    report.append(f"Coordinates:      Latitude: {details['whois']['latitude']}, Longitude: {details['whois']['longitude']}")
    report.append(f"Registration:     First Seen: {details['whois']['created_date']} | Updated: {details['whois']['updated_date']}")
    report.append("----------------------------------------------------------------------")
    report.append("VENDOR SECURITY LOGS FEED")
    report.append("----------------------------------------------------------------------")
    report.append(f"AbuseIPDB Feed:")
    report.append(f"  - Abuse Confidence:   {details['abuse']['abuse_score']}%")
    report.append(f"  - Abuse Scans Found:  {details['abuse']['total_reports']} reports")
    report.append(f"  - Subnet Scope:       {details['abuse']['domain']}")
    report.append(f"  - Ingestion Usage:    {details['abuse']['usage_type']}")
    report.append("")
    report.append(f"VirusTotal Telemetry:")
    report.append(f"  - AV Detections:      {details['vt']['malicious_count']} / {details['vt']['total_engines']} Engines")
    report.append(f"  - Reputation Score:   {details['vt']['reputation_score']}")
    report.append(f"  - Subnet CIDR Mask:   {details['vt']['network']}")
    report.append(f"  - Threat Tags:        {', '.join(details['vt']['tags']) if details['vt']['tags'] else 'None'}")
    report.append("----------------------------------------------------------------------")
    report.append("THREAT REMEDIATION PLAYBOOK")
    report.append("----------------------------------------------------------------------")
    for idx, rec in enumerate(details['recommendations'], 1):
        report.append(f"{idx}. [{rec['priority']} PRIORITY] - {rec['action']}")
        report.append(f"   Description: {rec['description']}")
        report.append("")
    report.append("----------------------------------------------------------------------")
    report.append("INVESTIGATION TIMELINE & ANALYSIS PROFILE")
    report.append("----------------------------------------------------------------------")
    report.append(f"Threat Feeds Scanned:    {details.get('sources_used', 'AbuseIPDB, VirusTotal, WHOIS')}")
    report.append(f"Analyst Actions Logged:  {details.get('actions_taken', 'Lookup Completed')}")
    report.append(f"Diagnostics Duration:    {details.get('duration_ms', 0)} ms")
    report.append(f"Severity Classification: {details.get('severity', 'Low').upper()}")
    report.append(f"Security Alert Tags:     {details.get('tags', 'None')}")
    report.append(f"Incident Notes log:\n{details.get('notes', 'No observations recorded.')}")
    report.append("======================================================================")
    report.append("                     [SECURE CONSOLE REPORT LOG]")
    report.append("======================================================================")
    
    return "\n".join(report)

def generate_txt_bulk(results, metadata, stats):
    """
    Generate a professional plaintext report summarizing bulk scans.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report = []
    report.append("======================================================================")
    report.append("          CYBER BLACK THREAT INTEL PLATFORM - BATCH INGESTION SUMMARY")
    report.append("======================================================================")
    report.append(f"Report Timestamp: {timestamp}")
    report.append(f"Source Filename:  {metadata['filename']}")
    report.append("----------------------------------------------------------------------")
    report.append("BATCH AGGREGATIONS")
    report.append("----------------------------------------------------------------------")
    report.append(f"Total Unique IPs Ingested: {stats['total']}")
    report.append(f"  - Safe Targets:          {stats['safe']} ({round((stats['safe']/stats['total'])*100, 1)}%)")
    report.append(f"  - Suspicious Targets:    {stats['suspicious']} ({round((stats['suspicious']/stats['total'])*100, 1)}%)")
    report.append(f"  - Malicious Targets:     {stats['malicious']} ({round((stats['malicious']/stats['total'])*100, 1)}%)")
    report.append("----------------------------------------------------------------------")
    report.append("THREAT REMEDIATION MATRIX")
    report.append("----------------------------------------------------------------------")
    if stats['malicious'] > 0:
        report.append(f"CRITICAL: {stats['malicious']} IP nodes classified as Malicious. PERIMETER BLOCK RECOMMENDED.")
    if stats['suspicious'] > 0:
        report.append(f"WARNING:  {stats['suspicious']} IP nodes classified as Suspicious. SURVEILLANCE AUDIT REGISTER RECOMMENDED.")
    if stats['malicious'] == 0 and stats['suspicious'] == 0:
        report.append("INFORMATION: All nodes analyzed as safe. Routine auditing operations continue.")
    report.append("")
    report.append("----------------------------------------------------------------------")
    report.append("NODE REPUTATION DIRECTORY")
    report.append("----------------------------------------------------------------------")
    report.append(f"{'IP ADDRESS':<20}{'SCORE':<8}{'CLASS':<15}{'ISP NETWORK':<30}{'COUNTRY':<15}")
    report.append("-" * 88)
    for row in results:
        ip = row['ip']
        score = f"{row['risk_score']}/100"
        classification = row['classification']
        isp = row['isp'][:28]
        country = row['country']
        report.append(f"{ip:<20}{score:<8}{classification:<15}{isp:<30}{country:<15}")
    report.append("======================================================================")
    report.append("                     [SECURE CONSOLE REPORT LOG]")
    report.append("======================================================================")
    
    return "\n".join(report)

def generate_html_print_individual(details):
    """
    Generates print-optimized HTML template representing the individual report.
    This bypasses sidebar graphics for high-quality standard white-background printing.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    rec_html = "".join([
        f"""
        <div style="margin-bottom: 12px; border-left: 3px solid #ff0055; padding-left: 10px;">
            <strong>[{rec['priority']} Priority] {rec['action']}</strong>
            <p style="margin: 4px 0 0 0; color: #555;">{rec['description']}</p>
        </div>
        """ for rec in details['recommendations']
    ])
    
    return f"""
    <html>
    <head>
        <title>Cyber Black Threat Intel Platform - Audit Report {details['ip']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.5; color: #111; padding: 40px; background: #fff; }}
            .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
            .section {{ margin-bottom: 25px; }}
            .section-title {{ font-size: 1.2em; font-weight: bold; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin-bottom: 12px; text-transform: uppercase; }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
            .col-full {{ grid-column: span 2; }}
            .field {{ margin-bottom: 8px; }}
            .label {{ color: #666; font-size: 0.9em; }}
            .value {{ font-weight: bold; }}
            .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; border: 1px solid #333; }}
        </style>
    </head>
    <body>
    <script>
        window.onload = function() {{
            window.print();
        }};
        window.onafterprint = function() {{
            window.close();
        }};
    </script>

        <div class="header">
            <h1 style="margin: 0; font-size: 1.8em;">CYBER BLACK THREAT INTEL PLATFORM</h1>
            <p style="margin: 5px 0 0 0; color: #555; font-size: 0.95em;">AI-Powered Threat Intelligence & Security Investigation Platform</p>
            <p style="margin: 5px 0 0 0; font-size: 0.85em; color: #888;">Generated: {timestamp}</p>
        </div>
        
        <div class="section">
            <div class="grid">
                <div class="field">
                    <span class="label">Target IP Address:</span><br>
                    <span class="value" style="font-size: 1.2em; font-family: monospace;">{details['ip']}</span>
                </div>
                <div class="field" style="text-align: right;">
                    <span class="label">Threat Classification:</span><br>
                    <span class="badge">{details['risk']['classification']} (Score: {details['risk']['score']}/100)</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Analyst findings summary</div>
            <div style="background: #f5f5f5; border-left: 4px solid #333; padding: 15px; font-family: monospace; font-size: 0.95em;">
                {details['summary']}
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Infrastructure profile</div>
            <div class="grid">
                <div class="field"><span class="label">ISP Network:</span> <span class="value">{details['whois']['isp']}</span></div>
                <div class="field"><span class="label">ASN ID:</span> <span class="value">{details['whois']['asn']} ({details['whois']['asn_org']})</span></div>
                <div class="field"><span class="label">Registered Owner:</span> <span class="value">{details['whois']['org']}</span></div>
                <div class="field"><span class="label">Origin Location:</span> <span class="value">{details['whois']['city']}, {details['whois']['region']}, {details['whois']['country']}</span></div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Security Feeds Telemetry</div>
            <div class="grid">
                <div class="field">
                    <strong>AbuseIPDB Feed:</strong><br>
                    <span class="label">Abuse Confidence:</span> <span class="value">{details['abuse']['abuse_score']}%</span><br>
                    <span class="label">Total Reports:</span> <span class="value">{details['abuse']['total_reports']} reports</span>
                </div>
                <div class="field">
                    <strong>VirusTotal Feed:</strong><br>
                    <span class="label">AV Detections:</span> <span class="value">{details['vt']['malicious_count']} / {details['vt']['total_engines']}</span><br>
                    <span class="label">Reputation Score:</span> <span class="value">{details['vt']['reputation_score']}</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Action Remediation Playbook</div>
            {rec_html}
        </div>
        
        <div class="section">
            <div class="section-title">Investigation Timeline & Profile</div>
            <div class="grid">
                <div class="field"><span class="label">Feeds Queried:</span> <span class="value">{details.get('sources_used', 'AbuseIPDB, VirusTotal, WHOIS')}</span></div>
                <div class="field"><span class="label">Actions Taken:</span> <span class="value">{details.get('actions_taken', 'Lookup Completed')}</span></div>
                <div class="field"><span class="label">Scan Duration:</span> <span class="value">{details.get('duration_ms', 0)} ms</span></div>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Analyst Notes & Incident Observations</div>
            <div class="grid">
                <div class="field"><span class="label">Severity Rating:</span> <span class="value" style="color: #ff0055; font-weight: bold;">{details.get('severity', 'Low').upper()}</span></div>
                <div class="field"><span class="label">Classification Tags:</span> <span class="value">{details.get('tags', 'None')}</span></div>
                <div class="col-full" style="margin-top: 8px; grid-column: span 2;">
                    <span class="label">Observations Log:</span>
                    <div style="background: #fafafa; border: 1px solid #eee; padding: 12px; margin-top: 4px; font-style: italic; white-space: pre-wrap;">
                        {details.get('notes') if details.get('notes') else 'No observation log recorded.'}
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

def generate_html_print_bulk(results, metadata, stats):
    """
    Generates print-optimized HTML layout summarizing bulk scans.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M')
    
    rows_html = "".join([
        f"""
        <tr>
            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-family: monospace;">{row['ip']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{row['classification']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-family: monospace;">{row['risk_score']}/100</td>
            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{row['isp']}</td>
            <td style="padding: 8px; border-bottom: 1px solid #ddd;">{row['country']}</td>
        </tr>
        """ for row in results
    ])
    
    return f"""
    <html>
    <head>
        <title>Cyber Black Threat Intel Platform - Bulk Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.5; color: #111; padding: 40px; background: #fff; }}
            .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
            .section {{ margin-bottom: 25px; }}
            .section-title {{ font-size: 1.2em; font-weight: bold; border-bottom: 1px solid #ddd; padding-bottom: 6px; margin-bottom: 12px; text-transform: uppercase; }}
            .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; text-align: center; margin-bottom: 25px; }}
            .metric-box {{ border: 1px solid #ddd; padding: 15px; border-radius: 4px; }}
            .metric-val {{ font-size: 1.5em; font-weight: bold; margin-bottom: 4px; }}
            .table-results {{ width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 0.9em; }}
            .table-results th {{ text-align: left; padding: 8px; background: #f5f5f5; border-bottom: 2px solid #ccc; }}
        </style>
    </head>
    <body>
    <script>
        window.onload = function() {{
            window.print();
        }};
        window.onafterprint = function() {{
            window.close();
        }};
    </script>
        <div class="header">
            <h1 style="margin: 0; font-size: 1.8em;">CYBER BLACK THREAT INTEL PLATFORM</h1>
            <p style="margin: 5px 0 0 0; color: #555; font-size: 0.95em;">AI-Powered Threat Intelligence & Security Investigation Platform - Bulk Diagnostic Audit</p>
            <p style="margin: 5px 0 0 0; font-size: 0.85em; color: #888;">Generated: {timestamp} | File Source: {metadata['filename']}</p>
        </div>
        
        <div class="section">
            <div class="section-title">Batch Threat Profile Aggregations</div>
            <div class="grid">
                <div class="metric-box">
                    <div class="metric-val">{stats['total']}</div>
                    <div style="color: #666; font-size: 0.8em; text-transform: uppercase;">Total Ingested</div>
                </div>
                <div class="metric-box" style="border-top: 3px solid #10b981;">
                    <div class="metric-val">{stats['safe']}</div>
                    <div style="color: #666; font-size: 0.8em; text-transform: uppercase;">Safe Nodes</div>
                </div>
                <div class="metric-box" style="border-top: 3px solid #f59e0b;">
                    <div class="metric-val">{stats['suspicious']}</div>
                    <div style="color: #666; font-size: 0.8em; text-transform: uppercase;">Suspicious Nodes</div>
                </div>
                <div class="metric-box" style="border-top: 3px solid #ff0055;">
                    <div class="metric-val">{stats['malicious']}</div>
                    <div style="color: #666; font-size: 0.8em; text-transform: uppercase;">Malicious Nodes</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Threat Remediation Playbook Summary</div>
            <div style="background: #f9f9f9; padding: 15px; border-left: 4px solid #333; font-size: 0.95em;">
                <strong>Playbook Remediations:</strong>
                <ul style="margin: 8px 0 0 0; padding-left: 20px; color: #444;">
                    <li>Configure firewalls to block all traffic coming from the {stats['malicious']} malicious IPs detected.</li>
                    <li>Surveillance logging and active packet inspections are recommended for the {stats['suspicious']} suspicious IPs.</li>
                </ul>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Analyzed IP Ingestion Directory</div>
            <table class="table-results">
                <thead>
                    <tr>
                        <th>IP Target Address</th>
                        <th>Classification</th>
                        <th>Risk Rating</th>
                        <th>ISP Infrastructure</th>
                        <th>Country</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """


def generate_txt_watchlist(watchlist_data):
    """
    Generate a plaintext report summarizing the watchlist.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report = []
    report.append("======================================================================")
    report.append("          CYBER BLACK THREAT INTEL PLATFORM - WATCHLIST AUDIT")
    report.append("======================================================================")
    report.append(f"Report Timestamp: {timestamp}")
    report.append(f"Total Watchlist Entries: {len(watchlist_data)}")
    report.append("----------------------------------------------------------------------")
    report.append(f"{'IP ADDRESS':<20}{'SCORE':<8}{'CLASS':<15}{'STATUS':<12}{'DATE ADDED':<12}")
    report.append("-" * 67)
    for row in watchlist_data:
        ip = row['ip']
        score = f"{row['risk_score']}/100"
        classification = row['classification']
        status = row['status']
        date = row['date_added'].split('T')[0]
        report.append(f"{ip:<20}{score:<8}{classification:<15}{status:<12}{date:<12}")
    report.append("======================================================================")
    return "\n".join(report)


def generate_txt_history(history_data):
    """
    Generate a plaintext report summarizing the investigation history.
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report = []
    report.append("======================================================================")
    report.append("          CYBER BLACK THREAT INTEL PLATFORM - HISTORY AUDIT")
    report.append("======================================================================")
    report.append(f"Report Timestamp: {timestamp}")
    report.append(f"Total Investigations: {len(history_data)}")
    report.append("----------------------------------------------------------------------")
    report.append(f"{'TIMESTAMP':<18}{'IP ADDRESS':<20}{'SCORE':<8}{'CLASS':<15}{'COUNTRY':<15}")
    report.append("-" * 76)
    for row in history_data:
        date = row['date'].split('T')[0] + " " + row['date'].split('T')[1][:5] if 'T' in row['date'] else row['date'][:16]
        ip = row['ip']
        score = f"{row['risk_score']}/100"
        classification = row['classification']
        country = row['country']
        report.append(f"{date:<18}{ip:<20}{score:<8}{classification:<15}{country:<15}")
    report.append("======================================================================")
    return "\n".join(report)

