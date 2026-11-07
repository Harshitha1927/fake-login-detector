import re
import urllib.parse

TRUSTED_DOMAINS = {
    'google.com', 'accounts.google.com', 'mail.google.com',
    'microsoft.com', 'login.microsoftonline.com', 'live.com',
    'apple.com', 'idmsa.apple.com', 'icloud.com',
    'amazon.com', 'amazon.in', 'amazon.co.uk',
    'paypal.com', 'www.paypal.com',
    'github.com', 'gitlab.com', 'bitbucket.org',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'netflix.com', 'spotify.com', 'dropbox.com',
    'adobe.com', 'yahoo.com', 'chase.com', 'bankofamerica.com',
    'wellsfargo.com', 'binance.com', 'coinbase.com', 'wikipedia.org',
    'stackoverflow.com', 'medium.com', 'reddit.com'
}

POPULAR_BRANDS = [
    'google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'chase', 'wellsfargo', 'binance', 'coinbase',
    'bankofamerica', 'twitter', 'linkedin', 'dropbox', 'adobe', 'yahoo',
    'whatsapp', 'telegram', 'outlook', 'github', 'ebay', 'spotify'
]

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'buzz',
    'loan', 'support', 'rest', 'fit', 'icu', 'surf', 'live', 'cam', 'vip',
    'bar', 'sbs', 'monster', 'cfd', 'quest', 'link', 'country', 'kim'
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bitly.com', 'cutt.ly', 'tiny.cc'
}

SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
    'account', 'banking', 'secure', 'security', 'update', 'wallet',
    'password', 'credential', 'billing', 'confirm', 'authentication',
    'authorize', 'recover', 'webscr', 'cmd=_login'
]

HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a', 'vv': 'w'
}

def normalize_typos(text):
    lowered = text.lower()
    for k, v in HOMOGLYPHS.items():
        lowered = lowered.replace(k, v)
    return lowered

def parse_url_components(url):
    cleaned_url = url.strip()
    if not cleaned_url.startswith(('http://', 'https://')):
        test_url = 'http://' + cleaned_url
        has_scheme = False
    else:
        test_url = cleaned_url
        has_scheme = True
        
    parsed = urllib.parse.urlparse(test_url)
    netloc = parsed.netloc.lower()
    if ':' in netloc:
        netloc = netloc.split(':')[0]
        
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip_host = bool(re.match(ip_pattern, netloc))
    
    if is_ip_host:
        registered_domain = netloc
        subdomain = ''
        tld = ''
    else:
        parts = netloc.split('.')
        if len(parts) >= 2:
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov', 'ac'] and len(parts[-1]) == 2:
                registered_domain = '.'.join(parts[-3:])
                subdomain = '.'.join(parts[:-3])
                tld = '.'.join(parts[-2:])
            else:
                registered_domain = '.'.join(parts[-2:])
                subdomain = '.'.join(parts[:-2])
                tld = parts[-1]
        else:
            registered_domain = netloc
            subdomain = ''
            tld = ''

    return {
        'original_url': cleaned_url,
        'scheme': parsed.scheme if has_scheme else 'http (unspecified)',
        'has_scheme': has_scheme,
        'netloc': netloc,
        'registered_domain': registered_domain,
        'subdomain': subdomain,
        'path': parsed.path or '/',
        'query': parsed.query,
        'tld': tld
    }

def extract_features(url):
    components = parse_url_components(url)
    url_lower = url.lower()
    netloc = components['netloc']
    path = components['path'].lower()
    registered_domain = components['registered_domain']
    subdomain = components['subdomain']
    tld = components['tld']

    url_len = len(url)
    domain_len = len(netloc)
    path_len = len(path)
    
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = 1 if re.match(ip_pattern, netloc) else 0
    
    count_dots = url.count('.')
    count_hyphens = url.count('-')
    count_hyphens_domain = netloc.count('-')
    count_at = 1 if '@' in url else 0
    count_double_slash = 1 if '//' in url[8:] else 0
    has_https = 1 if url.lower().startswith('https://') else 0
    
    subdomain_parts = [p for p in subdomain.split('.') if p]
    count_subdomains = len(subdomain_parts)
    
    is_suspicious_tld = 1 if (tld and tld in SUSPICIOUS_TLDS) else 0
    is_shortener = 1 if netloc in SHORTENERS else 0
    
    keyword_hits = [kw for kw in SENSITIVE_KEYWORDS if kw in url_lower]
    count_keywords = len(keyword_hits)
    
    digits_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digits_count / max(url_len, 1), 4)
    
    has_port = 1 if re.search(r':\d{2,5}', url) else 0
    
    brand_spoofed = 0
    spoofed_brand_name = ''
    norm_netloc = normalize_typos(netloc)
    
    is_trusted = 1 if (registered_domain in TRUSTED_DOMAINS or netloc in TRUSTED_DOMAINS) else 0
    
    if not is_trusted:
        for brand in POPULAR_BRANDS:
            if brand in registered_domain:
                continue
            if brand in subdomain or brand in norm_netloc or (brand in path and any(k in path for k in ['login', 'signin', 'verify', 'account'])):
                brand_spoofed = 1
                spoofed_brand_name = brand
                break
            
    has_client_server = 1 if any(w in url_lower for w in ['server', 'client', 'admin', 'portal', 'auth']) else 0
    path_depth = path.count('/')
    special_char_count = sum(url.count(c) for c in ['=', '_', '?', '%', '&', '~'])

    features = {
        'url_len': url_len,
        'domain_len': domain_len,
        'path_len': path_len,
        'is_ip': is_ip,
        'count_dots': count_dots,
        'count_hyphens': count_hyphens,
        'count_hyphens_domain': count_hyphens_domain,
        'count_at': count_at,
        'count_double_slash': count_double_slash,
        'has_https': has_https,
        'count_subdomains': count_subdomains,
        'is_suspicious_tld': is_suspicious_tld,
        'is_shortener': is_shortener,
        'count_keywords': count_keywords,
        'digit_ratio': digit_ratio,
        'has_port': has_port,
        'brand_spoofed': brand_spoofed,
        'has_client_server': has_client_server,
        'path_depth': path_depth,
        'special_char_count': special_char_count,
        'is_trusted': is_trusted
    }
    
    context = {
        'components': components,
        'keyword_hits': keyword_hits,
        'spoofed_brand_name': spoofed_brand_name,
        'is_trusted': bool(is_trusted)
    }
    
    return features, context

FEATURE_NAMES = [
    'url_len', 'domain_len', 'path_len', 'is_ip', 'count_dots',
    'count_hyphens', 'count_hyphens_domain', 'count_at', 'count_double_slash',
    'has_https', 'count_subdomains', 'is_suspicious_tld', 'is_shortener',
    'count_keywords', 'digit_ratio', 'has_port', 'brand_spoofed',
    'has_client_server', 'path_depth', 'special_char_count', 'is_trusted'
]

def explain_analysis(url, features, context, risk_probability):
    components = context['components']
    keyword_hits = context['keyword_hits']
    spoofed_brand = context['spoofed_brand_name']
    is_trusted = context['is_trusted']
    
    reasons_fake = []
    reasons_good = []
    
    # 1. IP Address Check
    if features['is_ip'] == 1:
        reasons_fake.append({
            'title': 'IP Address Used as Hostname',
            'desc': 'Host uses a direct raw IP address (' + components['netloc'] + ') instead of a registered domain. Legitimate companies almost never host login portals on raw IPs.',
            'severity': 'critical',
            'icon': 'alert-triangle'
        })
        
    # 2. Brand Spoofing Check
    if features['brand_spoofed'] == 1:
        brand_label = spoofed_brand.title()
        reasons_fake.append({
            'title': 'Brand Impersonation / Typosquatting (' + brand_label + ')',
            'desc': 'Detected brand keyword "' + brand_label + '" in subdomain or path, while the actual registered domain is "' + components['registered_domain'] + '". Attackers use this to trick users into trusting fraudulent portals.',
            'severity': 'critical',
            'icon': 'shield-alert'
        })
        
    # 3. @ Token Check
    if features['count_at'] == 1:
        reasons_fake.append({
            'title': 'Obfuscated "@" Redirect Token',
            'desc': 'The "@" symbol instructs browsers to ignore all preceding characters (usually a fake brand URL) and route to the following host.',
            'severity': 'critical',
            'icon': 'corner-down-right'
        })
        
    # 4. Double Slash Check
    if features['count_double_slash'] == 1:
        reasons_fake.append({
            'title': 'Suspicious Double Slash "//" in Path',
            'desc': 'Double slashes within the URL path indicate an open-redirect payload intended to redirect users to an unauthenticated external site.',
            'severity': 'high',
            'icon': 'repeat'
        })
        
    # 5. HTTPS Check
    if features['has_https'] == 0:
        reasons_fake.append({
            'title': 'Missing HTTPS Encryption',
            'desc': 'Page uses unencrypted HTTP. Legitimate authentication and login portals always require HTTPS (SSL/TLS) to prevent credential sniffing.',
            'severity': 'high',
            'icon': 'lock-open'
        })
        
    # 6. Subdomain Stacking
    if features['count_subdomains'] >= 3:
        reasons_fake.append({
            'title': 'Excessive Subdomain Stacking (' + str(features['count_subdomains']) + ' levels)',
            'desc': 'Deeply nested subdomains (' + components['subdomain'] + ') are commonly employed to push the real attacker domain out of view on smaller screens.',
            'severity': 'high',
            'icon': 'layers'
        })
        
    # 7. Suspicious TLD
    if features['is_suspicious_tld'] == 1:
        reasons_fake.append({
            'title': 'High-Risk Free/Abused TLD (.' + components['tld'] + ')',
            'desc': 'The top-level domain ".' + components['tld'] + '" is frequently abused in automated phishing kits due to free or disposable anonymous domain registration.',
            'severity': 'medium',
            'icon': 'globe'
        })
        
    # 8. Hyphens in Domain
    if features['count_hyphens_domain'] >= 2:
        reasons_fake.append({
            'title': 'Multiple Hyphens in Domain (' + str(features['count_hyphens_domain']) + ')',
            'desc': 'Excessive hyphens in the domain name ("' + components['netloc'] + '") often indicate fake domains created to stitch together brand terms.',
            'severity': 'medium',
            'icon': 'minus'
        })
        
    # 9. Credential Harvesting Words
    if features['count_keywords'] >= 2 and not is_trusted and (features['brand_spoofed'] == 1 or features['is_suspicious_tld'] == 1 or features['has_https'] == 0 or features['count_subdomains'] >= 2 or risk_probability >= 0.40):
        kw_preview = ', '.join(keyword_hits[:3])
        reasons_fake.append({
            'title': 'Credential Harvesting Trigger Words (' + kw_preview + ')',
            'desc': 'Contains urgent security or account-access keywords combined with suspicious domain architecture, typical of credential harvesting campaigns.',
            'severity': 'medium',
            'icon': 'key'
        })
        
    # 10. URL Shortener
    if features['is_shortener'] == 1:
        reasons_fake.append({
            'title': 'URL Shortener Masking (' + components['netloc'] + ')',
            'desc': 'Shortening services obscure the real destination, preventing victims and scanners from verifying the destination ahead of time.',
            'severity': 'medium',
            'icon': 'link'
        })
        
    # 11. Abnormal URL Length
    if features['url_len'] > 95 and not is_trusted:
        reasons_fake.append({
            'title': 'Abnormally Long URL (' + str(features['url_len']) + ' characters)',
            'desc': 'Excessive URL length is frequently used to bury malicious payload parameters or push suspicious tokens off-screen.',
            'severity': 'low',
            'icon': 'maximize-2'
        })

    # Legitimate / Good reasons
    if is_trusted:
        reasons_good.append({
            'title': 'Verified Official Brand Domain',
            'desc': 'The domain (' + components['registered_domain'] + ') matches a globally recognized, authentic high-trust enterprise infrastructure.',
            'icon': 'shield-check'
        })

    if features['has_https'] == 1:
        reasons_good.append({
            'title': 'Secured with HTTPS (SSL/TLS)',
            'desc': 'Communication is encrypted end-to-end, ensuring login credentials cannot be intercepted by eavesdroppers.',
            'icon': 'shield-check'
        })
        
    if features['is_ip'] == 0:
        reasons_good.append({
            'title': 'Legitimate Domain Name Hierarchy',
            'desc': 'Uses a standard registered domain (' + components['registered_domain'] + ') rather than an anonymous IP address.',
            'icon': 'check-circle'
        })
        
    if features['brand_spoofed'] == 0:
        reasons_good.append({
            'title': 'No Brand Typosquatting Detected',
            'desc': 'Host matches recognized domain boundaries without deceptive homoglyphs (like paypa1 or g00gle) in subdomains.',
            'icon': 'badge-check'
        })
        
    if features['count_subdomains'] <= 1:
        reasons_good.append({
            'title': 'Clean Subdomain Architecture',
            'desc': 'Standard domain depth with ' + str(features['count_subdomains']) + ' subdomain(s), without recursive spoofing chains.',
            'icon': 'check-circle'
        })
        
    if features['is_suspicious_tld'] == 0 and components['tld'] and features['is_ip'] == 0:
        reasons_good.append({
            'title': 'Reputable Top-Level Domain (.' + components['tld'] + ')',
            'desc': 'Registered under a reputable TLD (.' + components['tld'] + ') with verified registrar guidelines.',
            'icon': 'globe'
        })
        
    if features['count_at'] == 0 and features['count_double_slash'] == 0:
        reasons_good.append({
            'title': 'No Obfuscation or Redirection Tokens',
            'desc': 'Free of URL tricks such as "@" userinfo overrides or open-redirect double slashes.',
            'icon': 'check-circle'
        })

    if features['count_hyphens_domain'] == 0 and features['is_ip'] == 0:
        reasons_good.append({
            'title': 'Clean Domain Typography',
            'desc': 'Root domain contains zero hyphens, consistent with established corporate entities.',
            'icon': 'check-circle'
        })

    if features['url_len'] < 70:
        reasons_good.append({
            'title': 'Concise & Transparent URL (' + str(features['url_len']) + ' chars)',
            'desc': 'Compact path structure without hidden tracking strings or suspicious token stuffing.',
            'icon': 'check-circle'
        })

    # Determine verdict
    critical_flags = any(r['severity'] == 'critical' for r in reasons_fake)
    high_flags = sum(1 for r in reasons_fake if r['severity'] == 'high')
    
    if is_trusted and features['has_https'] == 1:
        verdict = 'LEGITIMATE / GOOD'
        verdict_badge = 'success'
        status_message = 'Safe! This is an authentic verified website login portal with valid encryption.'
        final_risk = min(risk_probability * 100, 3.5)
    elif risk_probability >= 0.60 or critical_flags or high_flags >= 2 or len(reasons_fake) >= 3:
        verdict = 'FAKE / PHISHING'
        verdict_badge = 'danger'
        status_message = 'Dangerous! This URL shows strong indicators of being a fraudulent login page or phishing portal.'
        final_risk = max(risk_probability * 100, 85.0 if critical_flags else 70.0)
    elif risk_probability >= 0.40 or len(reasons_fake) >= 1:
        verdict = 'SUSPICIOUS'
        verdict_badge = 'warning'
        status_message = 'Caution! This URL displays some unusual traits. Do not enter sensitive credentials without verifying.'
        final_risk = max(risk_probability * 100, 48.0)
    else:
        verdict = 'LEGITIMATE / GOOD'
        verdict_badge = 'success'
        status_message = 'Safe! This URL exhibits the structural characteristics of a genuine, legitimate website.'
        final_risk = min(risk_probability * 100, 15.0)

    return {
        'verdict': verdict,
        'verdict_badge': verdict_badge,
        'status_message': status_message,
        'risk_score': round(final_risk, 1),
        'reasons_fake': reasons_fake,
        'reasons_good': reasons_good,
        'components': components
    }
