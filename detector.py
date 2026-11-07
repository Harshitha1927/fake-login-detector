"""
Phishing and Fake Login Page Detection Engine.
Modular heuristic analysis for cybersecurity research and ethical hacking demonstrations.
"""
import re
import urllib.parse
import ipaddress
from typing import Dict, Any, List, Optional

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly",
    "goo.gl", "bitly.com", "shorte.st", "tr.im", "clck.ru"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "cf", "ml",
    "ga", "tk", "buzz", "racing", "vip", "icu", "wang", "casa",
    "zip", "mov", "link", "stream", "men", "trade", "bid", "party",
    "date", "faith", "review", "country", "kim", "cricket", "science"
}

BRAND_DOMAINS = {
    "google": ["google.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "accounts.google.com"],
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "login.live.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.ca", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "twitter": ["twitter.com", "x.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "github": ["github.com"],
}

SENSITIVE_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "banking", "verify",
    "verification", "account", "wallet", "security", "update",
    "credential", "password", "authenticate", "session", "confirm",
    "authorize", "validate", "recover", "billing", "secure-login",
    "passcode", "support-portal", "identity", "re-verify"
]


class PhishingDetector:
    """
    Analyzes URLs using 14 distinct security heuristics to detect fake login
    pages, brand spoofing, credential harvesting traps, and phishing attempts.
    """

    def __init__(self):
        self.brand_domains = BRAND_DOMAINS
        self.shorteners = KNOWN_SHORTENERS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.sensitive_keywords = SENSITIVE_KEYWORDS

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        """
        Runs the full heuristic audit on a URL and returns a comprehensive
        cybersecurity assessment dictionary.
        """
        raw_url = (raw_url or "").strip()
        if not raw_url:
            return {
                "valid": False,
                "error": "URL cannot be empty. Please enter a valid website link.",
                "url": raw_url
            }

        # Normalize URL (default to http if protocol missing)
        normalized_url = raw_url
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', raw_url):
            normalized_url = "http://" + raw_url

        try:
            parsed = urllib.parse.urlparse(normalized_url)
        except Exception as e:
            return {
                "valid": False,
                "error": f"Invalid URL structure: {str(e)}",
                "url": raw_url
            }

        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return {
                "valid": False,
                "error": f"Unsupported protocol: '{scheme}'. Only HTTP and HTTPS URLs are analyzed.",
                "url": raw_url
            }

        netloc = parsed.netloc.lower()
        if not netloc:
            return {
                "valid": False,
                "error": "Invalid URL: Hostname or domain could not be identified.",
                "url": raw_url
            }

        # Separate port from host if present
        host = netloc
        port = None
        if ":" in netloc and not netloc.endswith("]"):
            parts = netloc.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass

        path = parsed.path or "/"
        query = parsed.query or ""

        # Execute all 14 heuristics
        checks = []
        checks.append(self._check_ip_address(host))
        checks.append(self._check_url_length(raw_url, path))
        checks.append(self._check_url_shortener(host))
        checks.append(self._check_at_symbol(raw_url))
        checks.append(self._check_double_slash_redirect(path))
        checks.append(self._check_hyphen_in_domain(host))
        checks.append(self._check_subdomains(host))
        checks.append(self._check_port(port, scheme))
        checks.append(self._check_https(scheme))
        checks.append(self._check_suspicious_tld(host))
        checks.append(self._check_brand_impersonation(host, path, query))
        checks.append(self._check_punycode(host))
        checks.append(self._check_sensitive_keywords(host, path, query))
        checks.append(self._check_hex_encoding(raw_url))

        # Calculate risk score
        total_risk_score = 0
        critical_count = 0
        warning_count = 0
        pass_count = 0

        for chk in checks:
            if chk["status"] == "CRITICAL":
                total_risk_score += chk["weight"]
                critical_count += 1
            elif chk["status"] == "WARNING":
                total_risk_score += chk["weight"]
                warning_count += 1
            else:
                pass_count += 1

        # Check for correlated compound threats (e.g. Brand spoofing + login keywords)
        brand_check = next((c for c in checks if c["id"] == "brand_impersonation"), None)
        keyword_check = next((c for c in checks if c["id"] == "sensitive_keywords"), None)
        https_check = next((c for c in checks if c["id"] == "https_protocol"), None)

        if brand_check and brand_check["status"] != "SAFE":
            if keyword_check and keyword_check["status"] != "SAFE":
                total_risk_score += 15  # Credential trap bonus
            if https_check and https_check["status"] != "SAFE":
                total_risk_score += 10  # Plaintext login trap bonus

        # Normalize score into range [0, 100]
        risk_score = min(100, max(0, total_risk_score))

        # Determine Verdict
        if risk_score >= 61:
            verdict = "POTENTIAL PHISHING WEBSITE"
            verdict_badge = "danger"
            verdict_desc = "High probability of a fraudulent website or credential harvesting trap. Extreme caution advised!"
        elif risk_score >= 26:
            verdict = "SUSPICIOUS WEBSITE"
            verdict_badge = "warning"
            verdict_desc = "Multiple anomalous characteristics detected. Exercise caution and verify identity before proceeding."
        else:
            verdict = "SAFE WEBSITE"
            verdict_badge = "success"
            verdict_desc = "No major phishing or deceptive indicators detected. Standard browsing caution applies."

        # Generate Actionable Recommendations
        recommendations = self._generate_recommendations(checks, verdict)

        # Technical metadata summary
        extracted_info = {
            "scheme": scheme.upper(),
            "host": host,
            "port": port if port else ("443" if scheme == "https" else "80"),
            "path": path,
            "query": query if query else "None",
            "url_length": len(raw_url),
            "subdomain_count": max(0, len(host.split(".")) - 2) if not self._is_ip(host) else 0
        }

        return {
            "valid": True,
            "url": raw_url,
            "normalized_url": normalized_url,
            "risk_score": risk_score,
            "verdict": verdict,
            "verdict_badge": verdict_badge,
            "verdict_desc": verdict_desc,
            "summary": {
                "critical_flags": critical_count,
                "warning_flags": warning_count,
                "passed_checks": pass_count,
                "total_checks": len(checks)
            },
            "extracted_info": extracted_info,
            "checks": checks,
            "recommendations": recommendations
        }

    def _is_ip(self, host: str) -> bool:
        """Helper to test if host string is an IP address."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _check_ip_address(self, host: str) -> Dict[str, Any]:
        """Heuristic 1: Raw IP Address usage in Hostname."""
        if self._is_ip(host):
            return {
                "id": "ip_address",
                "name": "IP Address Hostname Check",
                "category": "Network Origin",
                "status": "CRITICAL",
                "weight": 35,
                "details": f"Host is a direct IP address ({host}) instead of an authenticated domain name.",
                "reason": "Legitimate institutions use registered domain names with TLS certificates. Attackers often deploy phishing kits on raw server IPs to avoid domain registration records."
            }
        if re.match(r'^(0x[0-9a-fA-F]+\.?)+$', host) or re.match(r'^[0-9]+$', host):
            return {
                "id": "ip_address",
                "name": "IP Address Hostname Check",
                "category": "Network Origin",
                "status": "CRITICAL",
                "weight": 35,
                "details": "Host uses integer or hex-encoded IP obfuscation.",
                "reason": "Hexadecimal or decimal IP formats are classic evasion techniques used to bypass naive security filters."
            }
        return {
            "id": "ip_address",
            "name": "IP Address Hostname Check",
            "category": "Network Origin",
            "status": "SAFE",
            "weight": 0,
            "details": f"Host '{host}' is a named domain, not a direct IP address.",
            "reason": "Passed standard domain name format validation."
        }

    def _check_url_length(self, raw_url: str, path: str) -> Dict[str, Any]:
        """Heuristic 2: Suspicious URL and Path Length."""
        length = len(raw_url)
        if length > 120:
            return {
                "id": "url_length",
                "name": "Abnormal URL Length Check",
                "category": "Obfuscation",
                "status": "CRITICAL",
                "weight": 15,
                "details": f"URL length is {length} characters (>120 limit).",
                "reason": "Extremely long URLs are commonly used in phishing campaigns to bury real domain information and encode victim tracking tokens."
            }
        elif length > 75:
            return {
                "id": "url_length",
                "name": "Abnormal URL Length Check",
                "category": "Obfuscation",
                "status": "WARNING",
                "weight": 8,
                "details": f"URL length is {length} characters (>75 limit).",
                "reason": "Longer than average URL. While common on some e-commerce platforms, phishing sites frequently use bloated links."
            }
        return {
            "id": "url_length",
            "name": "Abnormal URL Length Check",
            "category": "Obfuscation",
            "status": "SAFE",
            "weight": 0,
            "details": f"URL length ({length} characters) is within standard limits.",
            "reason": "Length conforms to standard web conventions."
        }

    def _check_url_shortener(self, host: str) -> Dict[str, Any]:
        """Heuristic 3: URL Shortening Services."""
        clean_host = host.lower()
        if clean_host.startswith("www."):
            clean_host = clean_host[4:]

        if clean_host in self.shorteners:
            return {
                "id": "url_shortener",
                "name": "URL Shortener Detection",
                "category": "Redirection Mask",
                "status": "WARNING",
                "weight": 25,
                "details": f"URL uses a known URL shortening provider ({clean_host}).",
                "reason": "Shorteners obscure the actual destination domain, preventing the user and security software from inspecting the destination endpoint prior to clicking."
            }
        return {
            "id": "url_shortener",
            "name": "URL Shortener Detection",
            "category": "Redirection Mask",
            "status": "SAFE",
            "weight": 0,
            "details": f"Host '{host}' is not a recognized URL shortener.",
            "reason": "Destination domain is visible and not masked by an intermediary shortener."
        }

    def _check_at_symbol(self, raw_url: str) -> Dict[str, Any]:
        """Heuristic 4: Presence of '@' symbol in URL."""
        if "@" in raw_url:
            return {
                "id": "at_symbol",
                "name": "Basic Auth '@' Deception Symbol",
                "category": "Authority Spoofing",
                "status": "CRITICAL",
                "weight": 30,
                "details": "URL contains the '@' symbol in authority string.",
                "reason": "The '@' character instructs browsers to treat everything before it as login credentials, routing the browser to the address following the '@'. Phishers abuse this to trick users into seeing trusted domains."
            }
        return {
            "id": "at_symbol",
            "name": "Basic Auth '@' Deception Symbol",
            "category": "Authority Spoofing",
            "status": "SAFE",
            "weight": 0,
            "details": "No '@' credential hijacking symbol found.",
            "reason": "Standard URL authority format without inline credential disguises."
        }

    def _check_double_slash_redirect(self, path: str) -> Dict[str, Any]:
        """Heuristic 5: Double Slash '//' in URL Path."""
        if "//" in path:
            return {
                "id": "double_slash",
                "name": "Path Redirection Check ('//')",
                "category": "Redirection Mask",
                "status": "WARNING",
                "weight": 15,
                "details": "URL path contains unexpected double slashes ('//').",
                "reason": "Double slashes inside path parameters frequently signal open redirection vectors or forward-to-phishing URL tricks."
            }
        return {
            "id": "double_slash",
            "name": "Path Redirection Check ('//')",
            "category": "Redirection Mask",
            "status": "SAFE",
            "weight": 0,
            "details": "URL path does not contain illegal double-slash redirects.",
            "reason": "URL path syntax follows RFC 3986 path standards."
        }

    def _check_hyphen_in_domain(self, host: str) -> Dict[str, Any]:
        """Heuristic 6: Hyphen Count in Domain Name."""
        hyphen_count = host.count("-")
        if hyphen_count >= 3:
            return {
                "id": "hyphen_domain",
                "name": "Domain Hyphen Abuse Check",
                "category": "Typosquatting",
                "status": "CRITICAL",
                "weight": 20,
                "details": f"Domain contains {hyphen_count} hyphens ('-').",
                "reason": "Multiple hyphens in a domain (e.g., 'secure-paypal-login-verify.com') are overwhelmingly typical of typosquatting and brand impersonation domains."
            }
        elif hyphen_count in (1, 2):
            return {
                "id": "hyphen_domain",
                "name": "Domain Hyphen Abuse Check",
                "category": "Typosquatting",
                "status": "WARNING",
                "weight": 10,
                "details": f"Domain contains {hyphen_count} hyphen(s).",
                "reason": "Hyphenated domain names are occasionally used by attackers to combine brand names with security terms."
            }
        return {
            "id": "hyphen_domain",
            "name": "Domain Hyphen Abuse Check",
            "category": "Typosquatting",
            "status": "SAFE",
            "weight": 0,
            "details": "No suspicious hyphens found in domain name.",
            "reason": "Clean domain naming structure."
        }

    def _check_subdomains(self, host: str) -> Dict[str, Any]:
        """Heuristic 7: Excessive Subdomain Nesting."""
        if self._is_ip(host):
            return {
                "id": "subdomain_count",
                "name": "Subdomain Stacking Check",
                "category": "Domain Architecture",
                "status": "SAFE",
                "weight": 0,
                "details": "Host is an IP address; subdomain analysis bypassed.",
                "reason": "Evaluated separately under IP check."
            }
        parts = host.split(".")
        subdomain_count = max(0, len(parts) - 2)
        if subdomain_count >= 4:
            return {
                "id": "subdomain_count",
                "name": "Subdomain Stacking Check",
                "category": "Domain Architecture",
                "status": "CRITICAL",
                "weight": 20,
                "details": f"Domain has {subdomain_count} nested subdomains ({host}).",
                "reason": "Multi-level subdomain nesting (e.g. 'login.verify.account.chase.evil.com') is used to mislead victims on mobile browsers where only the prefix is visible."
            }
        elif subdomain_count == 3:
            return {
                "id": "subdomain_count",
                "name": "Subdomain Stacking Check",
                "category": "Domain Architecture",
                "status": "WARNING",
                "weight": 10,
                "details": f"Domain has {subdomain_count} subdomains.",
                "reason": "Higher than average subdomain depth. Common in complex infrastructure but also used in deceptive URL crafting."
            }
        return {
            "id": "subdomain_count",
            "name": "Subdomain Stacking Check",
            "category": "Domain Architecture",
            "status": "SAFE",
            "weight": 0,
            "details": f"Domain has normal subdomain depth ({subdomain_count} subdomains).",
            "reason": "Typical domain hierarchy."
        }

    def _check_port(self, port: Optional[int], scheme: str) -> Dict[str, Any]:
        """Heuristic 8: Non-Standard Web Ports."""
        if port is None:
            return {
                "id": "port_check",
                "name": "Port Verification",
                "category": "Network Service",
                "status": "SAFE",
                "weight": 0,
                "details": "Default standard port in use (80 for HTTP, 443 for HTTPS).",
                "reason": "Service operates on official designated web ports."
            }
        standard_ports = [80, 443, 8080, 8443, 3000, 5000, 5173]
        if port not in standard_ports:
            return {
                "id": "port_check",
                "name": "Port Verification",
                "category": "Network Service",
                "status": "WARNING",
                "weight": 15,
                "details": f"URL targets non-standard port {port}.",
                "reason": "Legitimate consumer login pages almost exclusively run on port 443. Unusual ports often indicate rogue daemons, backdoors, or testing servers."
            }
        return {
            "id": "port_check",
            "name": "Port Verification",
            "category": "Network Service",
            "status": "SAFE",
            "weight": 0,
            "details": f"Port {port} is recognized for standard web traffic.",
            "reason": "Acceptable port usage."
        }

    def _check_https(self, scheme: str) -> Dict[str, Any]:
        """Heuristic 9: Transport Encryption (HTTPS)."""
        if scheme == "http":
            return {
                "id": "https_protocol",
                "name": "Transport Encryption (HTTPS)",
                "category": "Cryptographic Security",
                "status": "WARNING",
                "weight": 15,
                "details": "Connection uses unencrypted HTTP protocol.",
                "reason": "Legitimate login pages MUST use HTTPS to protect credentials in transit. Submitting passwords over plain HTTP exposes data to eavesdropping and Man-in-the-Middle (MitM) attacks."
            }
        return {
            "id": "https_protocol",
            "name": "Transport Encryption (HTTPS)",
            "category": "Cryptographic Security",
            "status": "SAFE",
            "weight": 0,
            "details": "Encrypted HTTPS protocol in use.",
            "reason": "Traffic is protected by TLS encryption."
        }

    def _check_suspicious_tld(self, host: str) -> Dict[str, Any]:
        """Heuristic 10: Suspicious or High-Abuse TLDs."""
        parts = host.split(".")
        tld = parts[-1].lower() if parts else ""

        if tld in self.suspicious_tlds:
            return {
                "id": "suspicious_tld",
                "name": "High-Risk TLD Check",
                "category": "Reputation",
                "status": "CRITICAL",
                "weight": 20,
                "details": f"Domain utilizes a high-abuse TLD (.{tld}).",
                "reason": f"TLDs such as .{tld} exhibit high rates of spam and automated phishing registration due to low acquisition costs and lenient registrar policies."
            }
        return {
            "id": "suspicious_tld",
            "name": "High-Risk TLD Check",
            "category": "Reputation",
            "status": "SAFE",
            "weight": 0,
            "details": f"Top-level domain (.{tld}) is standard.",
            "reason": "TLD has normal commercial and institutional reputation."
        }

    def _check_brand_impersonation(self, host: str, path: str, query: str) -> Dict[str, Any]:
        """Heuristic 11: Brand Name Impersonation & Typosquatting."""
        combined_text = f"{host} {path} {query}".lower()

        for brand, legitimate_domains in self.brand_domains.items():
            if re.search(r'\b' + re.escape(brand) + r'\b', combined_text) or brand in host:
                is_legitimate = False
                for legit in legitimate_domains:
                    if host == legit or host.endswith("." + legit):
                        is_legitimate = True
                        break

                if not is_legitimate:
                    return {
                        "id": "brand_impersonation",
                        "name": "Brand Impersonation & Spoofing",
                        "category": "Identity Fraud",
                        "status": "CRITICAL",
                        "weight": 40,
                        "details": f"Brand '{brand.capitalize()}' detected in URL, but the actual domain '{host}' is NOT authorized by {brand.capitalize()}.",
                        "reason": f"Attackers use recognizable brand names like '{brand}' in subdomains or deceptive URLs (e.g. '{brand}-login.xyz') to trick victims into surrendering account credentials."
                    }

        return {
            "id": "brand_impersonation",
            "name": "Brand Impersonation & Spoofing",
            "category": "Identity Fraud",
            "status": "SAFE",
            "weight": 0,
            "details": "No unauthorized brand trademark abuse detected in hostname.",
            "reason": "No evidence of high-profile brand mimicry."
        }

    def _check_punycode(self, host: str) -> Dict[str, Any]:
        """Heuristic 12: Punycode / IDN Homograph Attack."""
        if "xn--" in host:
            return {
                "id": "punycode_homograph",
                "name": "Punycode / Homograph Attack",
                "category": "Visual Spoofing",
                "status": "CRITICAL",
                "weight": 30,
                "details": f"Domain uses Punycode encoding prefix ('xn--'): {host}",
                "reason": "Internationalized Domain Names (IDNs) can mimic legitimate Latin characters with identical-looking Cyrillic or Greek glyphs (e.g., Cyrillic 'а' vs Latin 'a')."
            }
        try:
            host.encode('ascii')
        except UnicodeEncodeError:
            return {
                "id": "punycode_homograph",
                "name": "Punycode / Homograph Attack",
                "category": "Visual Spoofing",
                "status": "WARNING",
                "weight": 20,
                "details": "Domain contains non-ASCII characters outside standard alphanumeric charset.",
                "reason": "Non-standard unicode characters in hostnames can be leveraged in homoglyph deception."
            }
        return {
            "id": "punycode_homograph",
            "name": "Punycode / Homograph Attack",
            "category": "Visual Spoofing",
            "status": "SAFE",
            "weight": 0,
            "details": "Clean ASCII character set without Punycode disguise.",
            "reason": "No visual homograph deception indicators."
        }

    def _check_sensitive_keywords(self, host: str, path: str, query: str) -> Dict[str, Any]:
        """Heuristic 13: Sensitive Login and Credential Keywords."""
        full_text = f"{host} {path} {query}".lower()
        found_keywords = []

        for kw in self.sensitive_keywords:
            if re.search(r'\b' + re.escape(kw) + r'\b', full_text) or kw in host or kw in path:
                if kw not in found_keywords:
                    found_keywords.append(kw)

        if len(found_keywords) >= 3:
            return {
                "id": "sensitive_keywords",
                "name": "Sensitive Credential Keywords",
                "category": "Social Engineering",
                "status": "CRITICAL",
                "weight": 25,
                "details": f"Multiple sensitive keywords detected: {', '.join(found_keywords[:5])}",
                "reason": "Concentration of terms like 'verify', 'account', 'password', 'login' strongly indicates an aggressive credential solicitation mechanism."
            }
        elif len(found_keywords) in (1, 2):
            return {
                "id": "sensitive_keywords",
                "name": "Sensitive Credential Keywords",
                "category": "Social Engineering",
                "status": "WARNING",
                "weight": 12,
                "details": f"Sensitive authentication keyword(s) detected: {', '.join(found_keywords)}",
                "reason": "Login/account terms are legitimate on real portals, but require heightened verification if combined with unverified domains."
            }
        return {
            "id": "sensitive_keywords",
            "name": "Sensitive Credential Keywords",
            "category": "Social Engineering",
            "status": "SAFE",
            "weight": 0,
            "details": "No aggressive credential harvesting patterns found.",
            "reason": "Absence of typical phishing lure tokens."
        }

    def _check_hex_encoding(self, raw_url: str) -> Dict[str, Any]:
        """Heuristic 14: Hexadecimal and Percent-Encoding Obfuscation."""
        hex_matches = re.findall(r'%[0-9a-fA-F]{2}', raw_url)
        hex_count = len(hex_matches)

        if hex_count >= 5:
            return {
                "id": "hex_encoding",
                "name": "Encoding Obfuscation Check",
                "category": "Evasion Technique",
                "status": "WARNING",
                "weight": 15,
                "details": f"URL contains {hex_count} percent-encoded hex sequences.",
                "reason": "Heavy percent-encoding is frequently used to conceal malicious strings or evade web application firewall (WAF) pattern matching."
            }
        return {
            "id": "hex_encoding",
            "name": "Encoding Obfuscation Check",
            "category": "Evasion Technique",
            "status": "SAFE",
            "weight": 0,
            "details": f"Standard character encoding ({hex_count} encoded tokens).",
            "reason": "No anomalous evasion encoding detected."
        }

    def _generate_recommendations(self, checks: List[Dict[str, Any]], verdict: str) -> List[str]:
        """Produces tailored, actionable cybersecurity defense guidance."""
        recs = []

        if verdict == "POTENTIAL PHISHING WEBSITE":
            recs.append("🚨 DO NOT enter any usernames, passwords, credit card numbers, or OTPs on this website.")
            recs.append("⚠️ Check the browser address bar carefully: the domain is not authorized by the brand it claims to represent.")
            recs.append("🛑 Immediately close the webpage and delete any email or SMS that sent you this link.")

        for chk in checks:
            if chk["id"] == "https_protocol" and chk["status"] != "SAFE":
                recs.append("🔒 Never submit login credentials over HTTP; ensure the lock icon (HTTPS) is present and valid.")
            elif chk["id"] == "brand_impersonation" and chk["status"] != "SAFE":
                recs.append("🔍 Always navigate directly to official websites by typing their verified domain into the address bar rather than clicking external links.")
            elif chk["id"] == "url_shortener" and chk["status"] != "SAFE":
                recs.append("🔗 Expand shortened URLs using link-preview services before clicking to inspect where they lead.")
            elif chk["id"] == "ip_address" and chk["status"] != "SAFE":
                recs.append("🌐 Legitimate organizations virtually never ask customers to log into raw IP addresses. Avoid this site.")
            elif chk["id"] == "punycode_homograph" and chk["status"] != "SAFE":
                recs.append("👀 Watch out for lookalike letters (homographs) from other alphabets masquerading as Latin characters.")

        if not recs:
            recs.append("✅ Always enable Two-Factor Authentication (2FA) or Passkeys to protect your accounts even if a password is leaked.")
            recs.append("🛡️ Use a reputable password manager that automatically refuses to auto-fill credentials on unverified domains.")

        recs.append("⚠️ Academic Disclaimer: URL-based heuristic analysis detects many common indicators, but advanced targeted attacks may use compromised legitimate domains. Always exercise vigilance.")

        return recs
