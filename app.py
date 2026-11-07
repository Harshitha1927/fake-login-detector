"""
Fake Login Page Detector - Flask Web Server & API.
Cybersecurity educational and detection application.
"""
import os
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from core.detector import PhishingDetector

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
detector = PhishingDetector()

# Example URLs for demonstration
SAMPLE_URLS = [
    {
        "category": "SAFE",
        "title": "Google Official Portal",
        "url": "https://accounts.google.com/signin",
        "desc": "Legitimate authentication endpoint with HTTPS, official domain, and standard architecture."
    },
    {
        "category": "SAFE",
        "title": "GitHub Login",
        "url": "https://github.com/login",
        "desc": "Official developer platform authentication page with valid TLS and trusted domain."
    },
    {
        "category": "SUSPICIOUS",
        "title": "Shortened Link",
        "url": "https://bit.ly/secure-banking-portal-verification",
        "desc": "Masked destination concealing true destination server, common vector for phishing lures."
    },
    {
        "category": "PHISHING",
        "title": "PayPal Fake Security Alert",
        "url": "http://paypal-security-update.account-verification.xyz/login.php",
        "desc": "Multi-vector phishing: unauthorized domain brand mimicry, unencrypted HTTP, high-risk .xyz TLD, credential harvesting path."
    },
    {
        "category": "PHISHING",
        "title": "Direct IP Login Portal",
        "url": "http://192.168.1.105/bank-login-secure/verify-identity.html",
        "desc": "Host uses a raw numerical IP address without domain TLS authentication, combined with credential harvest keywords."
    },
    {
        "category": "PHISHING",
        "title": "Basic Auth Spoofing ('@' trick)",
        "url": "http://microsoft.com@cloud-account-update-portal.top/signin",
        "desc": "Abuses RFC basic auth syntax to make 'microsoft.com' look like host while destination is 'cloud-account-update-portal.top'."
    }
]


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@app.route('/')
def index():
    """Serves the primary cybersecurity detector web interface."""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def scan_url():
    """
    REST API endpoint for URL phishing analysis.
    Accepts JSON: {"url": "..."}
    """
    if not request.is_json:
        return jsonify({
            "valid": False,
            "error": "Request payload must be JSON with a 'url' field."
        }), 400

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({
            "valid": False,
            "error": "URL cannot be empty. Please enter or paste a valid website URL."
        }), 400

    try:
        result = detector.analyze(url)
        result["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
        return jsonify(result)
    except Exception as e:
        return jsonify({
            "valid": False,
            "error": f"Internal scan engine error: {str(e)}"
        }), 500


@app.route('/api/examples', methods=['GET'])
def get_examples():
    """Returns curated demo URLs representing Safe, Suspicious, and Phishing categories."""
    return jsonify({
        "status": "success",
        "examples": SAMPLE_URLS
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """System health check and diagnostic endpoint."""
    return jsonify({
        "status": "online",
        "system": "Fake Login Page Detector",
        "version": "1.0.0",
        "active_rules": 14,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[*] Starting Fake Login Page Detector on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
