# Fake Login Page Detector (PhishSentry)

A full-stack cybersecurity web application built from scratch for **Ethical Hacking** and defensive security education. It analyzes target website URLs in real-time using a 14-point heuristic phishing detection engine, computes a risk exposure score (0–100), classifies threats, and generates actionable security advice.

---

## Key Features

1. **Cybersecurity-Themed Responsive Interface**:
   - Modern dark navy and black palette with cyber-cyan and electric-blue accents.
   - Animated circular SVG risk gauge with dynamic color grading (Safe, Suspicious, Phishing).
   - Real-time radar scanning animation with step-by-step heuristic terminal logs.
   - Fully responsive across desktop, tablet, and mobile browsers.

2. **14 Multi-Vector Detection Heuristics**:
   - **IP Address as Hostname**: Detects raw numerical or obfuscated hex/octal server IPs.
   - **Abnormal URL Length**: Flags excessively long URLs (>75 and >120 characters) and path bloating.
   - **Known URL Shorteners**: Identifies redirect masking services (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
   - **Authority Deception (`@` Symbol)**: Flags HTTP basic authentication credential disguises.
   - **Double Slash Redirect (`//`)**: Identifies illicit URL redirection sequences in paths.
   - **Hyphen Abuse**: Detects typosquatting and deceptive multi-hyphen brand combinations.
   - **Subdomain Stacking**: Flags deep nesting (>3 subdomains) used to deceive mobile users.
   - **Non-Standard Ports**: Detects abnormal web daemon ports (e.g., `:8080`, `:8888`, `:21`).
   - **Transport Layer Security (HTTPS)**: Audits protocol encryption for sensitive login portals.
   - **High-Risk Phishing TLDs**: Audits top-level domains with high spam/abuse rates (`.xyz`, `.top`, `.click`, `.loan`, `.work`, `.gq`, etc.).
   - **Brand Impersonation & Typosquatting**: Checks for unauthorized brand names (Google, PayPal, Microsoft, Apple, Amazon, Netflix, etc.) on unverified domains.
   - **Punycode / IDN Homograph Attack**: Identifies Cyrillic/Greek lookalikes and `xn--` encoding.
   - **Sensitive Credential Keywords**: Detects aggressive lure keywords (`login`, `verify`, `account`, `password`, `wallet`, `banking`, etc.).
   - **Hex / Percent-Encoding Obfuscation**: Flags excessive `%` escape sequences designed to evade filters.

3. **Threat Classification & Risk Scoring**:
   - `0 - 25`: **SAFE WEBSITE** (Low Risk - Green)
   - `26 - 60`: **SUSPICIOUS WEBSITE** (Medium Risk - Amber)
   - `61 - 100`: **POTENTIAL PHISHING WEBSITE** (High Risk - Neon Red)

4. **Additional Capabilities**:
   - One-click demo test buttons for safe, suspicious, and phishing scenarios.
   - Local scan history with persistent session storage and re-scan capability.
   - Step-by-step visual educational guide: "Anatomy of a Fake Login Page Attack".
   - REST API endpoints (`/api/scan`, `/api/examples`, `/api/health`).
   - Zero credential harvesting: operates strictly as a defensive diagnostic engine.

---

## Architecture

```
fake-login-detector/
├── core/
│   ├── __init__.py
│   └── detector.py         # 14-rule heuristic phishing detection engine
├── static/
│   ├── css/
│   │   └── style.css       # Cybersecurity dark theme & animations
│   └── js/
│       └── app.js          # Interactive frontend logic & local history
├── templates/
│   └── index.html          # Main web application dashboard
├── tests/
│   ├── __init__.py
│   └── test_detector.py    # Automated test suite
├── app.py                  # Flask server & REST API
├── wsgi.py                 # Production WSGI entry point
├── Procfile                # Heroku/Render process declaration
├── render.yaml             # Render cloud deployment configuration
├── requirements.txt        # Python dependencies
└── README.md               # Documentation
```

---

## Local Setup & Running

### 1. Prerequisites
- Python 3.9+ (Python 3.13 tested)

### 2. Run Locally
```bash
python app.py
```
Open your browser and navigate to: `http://127.0.0.1:5000`

### 3. Run Automated Tests
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## REST API Documentation

### `POST /api/scan`
Analyzes a URL and returns detection results.

**Request:**
```json
{
  "url": "http://paypal-security-update.account-verification.xyz/login.php"
}
```

**Response:**
```json
{
  "valid": true,
  "url": "http://paypal-security-update.account-verification.xyz/login.php",
  "risk_score": 90,
  "verdict": "POTENTIAL PHISHING WEBSITE",
  "verdict_badge": "danger",
  "summary": {
    "critical_flags": 3,
    "warning_flags": 2,
    "passed_checks": 9,
    "total_checks": 14
  },
  "extracted_info": { ... },
  "checks": [ ... ],
  "recommendations": [ ... ]
}
```

### `GET /api/examples`
Returns pre-configured sample URLs for instant demonstration.

### `GET /api/health`
Returns system health, active rules count, and status.

---

## Ethical Hacking Subject Context

This project demonstrates defensive URL reconnaissance and lexical threat modeling against social engineering and credential theft. It serves as an educational asset highlighting the mechanics of modern phishing campaigns and countermeasures for user defense.
