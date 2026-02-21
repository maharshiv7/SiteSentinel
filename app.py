from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests
from urllib.parse import urlparse
import os
import whois
import socket  # <-- NEW: Imported socket for real Port Scanning

app = Flask(__name__)
CORS(app)

# Create an absolute, foolproof path to your reports folder
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')

if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

def format_date(date_obj):
    if isinstance(date_obj, list):
        return date_obj[0].strftime('%Y-%m-%d')
    elif date_obj:
        return date_obj.strftime('%Y-%m-%d')
    return "Unknown"

@app.route('/scan', methods=['GET'])
def scan_url():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400
        
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url

    try:
        # 1. Header Analysis
        response = requests.get(target_url, timeout=5)
        headers = response.headers
        results = []
        score = 100
        
        if 'Strict-Transport-Security' in headers:
            results.append({"name": "Strict-Transport-Security", "status": "Secure", "icon": "fa-check", "color": "text-emerald-500"})
        else:
            results.append({"name": "Strict-Transport-Security", "status": "Missing (Downgrade Risk)", "icon": "fa-xmark", "color": "text-red-500"})
            score -= 20

        if 'X-Frame-Options' in headers:
            results.append({"name": "X-Frame-Options", "status": "Secure", "icon": "fa-check", "color": "text-emerald-500"})
        else:
            results.append({"name": "X-Frame-Options", "status": "Missing (Clickjacking Risk)", "icon": "fa-xmark", "color": "text-red-500"})
            score -= 25
            
        if 'Content-Security-Policy' in headers:
            results.append({"name": "Content-Security-Policy", "status": "Secure", "icon": "fa-check", "color": "text-emerald-500"})
        else:
            results.append({"name": "Content-Security-Policy", "status": "Missing (XSS Risk)", "icon": "fa-xmark", "color": "text-red-500"})
            score -= 30

        if score >= 90: grade, color, msg = "A", "text-emerald-500", "Excellent OpSec. Headers look great."
        elif score >= 70: grade, color, msg = "B", "text-blue-500", "Good, but missing some modern protections."
        elif score >= 50: grade, color, msg = "C", "text-yellow-500", "Moderate risk. Multiple headers missing."
        else: grade, color, msg = "F", "text-red-500", "High risk. Critical security headers are absent."

        # Extract domain name for WHOIS
        domain = urlparse(target_url).netloc or target_url.replace('https://', '').replace('http://', '')
        if domain.startswith('www.'):
            domain = domain[4:]

        # 2. WHOIS Lookup
        domain_info = {}
        try:
            w = whois.whois(domain)
            domain_info['registrar'] = w.registrar or "Unknown/Private"
            domain_info['creation_date'] = format_date(w.creation_date)
            domain_info['expiration_date'] = format_date(w.expiration_date)
        except Exception as e:
            domain_info = {"registrar": "Lookup Failed", "creation_date": "N/A", "expiration_date": "N/A"}

        # 3. FILE I/O: Create the report file
        report_filename = f"{domain}_report.txt"
        filepath = os.path.join(REPORTS_DIR, report_filename)
        
        with open(filepath, "w") as file:
            file.write(f"--- SITESENTINEL SECURITY REPORT ---\n")
            file.write(f"Target URL: {target_url}\n")
            file.write(f"Final Grade: {grade} ({score}/100)\n")
            file.write(f"Summary: {msg}\n\n")
            
            file.write(f"--- DOMAIN INTELLIGENCE (WHOIS) ---\n")
            file.write(f"Registrar: {domain_info['registrar']}\n")
            file.write(f"Created On: {domain_info['creation_date']}\n")
            file.write(f"Expires On: {domain_info['expiration_date']}\n\n")
            
            file.write(f"--- HEADER BREAKDOWN ---\n")
            for item in results:
                file.write(f"- {item['name']}: {item['status']}\n")

        return jsonify({
            "status": "success",
            "grade": grade,
            "message": msg,
            "color": color,
            "headers": results,
            "domain_info": domain_info,
            "report_file": report_filename
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"status": "error", "message": "Could not connect to the website. Make sure it is a valid URL."}), 400

@app.route('/download', methods=['GET'])
def download_report():
    filename = request.args.get('file')
    if not filename:
        return "No file specified", 400
        
    filepath = os.path.join(REPORTS_DIR, filename)
    
    if not os.path.exists(filepath):
        return "File not found", 404
        
    return send_file(filepath, as_attachment=True)


# --- NEW: LIVE PORT SCANNER ROUTE ---
@app.route('/port-scan', methods=['GET'])
def port_scan():
    target = request.args.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400

    # Clean the URL
    target = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    try:
        # Translate the domain (e.g., scanme.nmap.org) into its IP Address
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": "Could not resolve hostname. Is the domain correct?"}), 400

    # The exact network doors (Ports) we will knock on
    ports_to_scan = {
        21: ("ftp", "High Risk"),
        22: ("ssh", "Medium Risk"),
        80: ("http", "Low Risk"),
        443: ("https", "Low Risk"),
        3306: ("mysql", "High Risk")
    }

    results = []
    
    for port, (service, risk) in ports_to_scan.items():
        # Create a network socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0) # Wait only 1 second per door
        
        # Try to open the door. '0' means it opened successfully!
        result = sock.connect_ex((target_ip, port))
        
        if result == 0:
            state = "open"
            state_color = "text-emerald-500"
            risk_color = "text-yellow-500" if risk == "Medium Risk" else "text-red-500" if risk == "High Risk" else "text-gray-500"
        else:
            state = "filtered/closed"
            state_color = "text-gray-500"
            risk_color = "text-emerald-500"
            risk = "Secure"

        results.append({
            "port": port,
            "state": state,
            "service": service,
            "risk": risk,
            "state_color": state_color,
            "risk_color": risk_color
        })
        sock.close()

    return jsonify({
        "status": "success",
        "target_ip": target_ip,
        "scan_results": results
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)