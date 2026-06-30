# index.py - Main API handler for Vercel
import os
import re
import socket
import requests
import dns.resolver
import whois
from hashlib import md5
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Colour codes ────────────────────────────────────────────────────
RED = "\033[31m"
GRN = "\033[32m"
YEL = "\033[33m"
BLU = "\033[34m"
MAG = "\033[35m"
CYN = "\033[36m"
RST = "\033[0m"
WHT = "\033[37m"

# ── Disposable domains ─────────────────────────────────────────────
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "10minutemail.com", "yopmail.com",
    "trashmail.com", "guerrillamail.com", "sharklasers.com", "getnada.com",
    "temp-mail.org", "mailnesia.com", "guerrillamail.biz", "guerrillamail.net",
    "guerrillamail.org", "spamgourmet.com", "spambox.com", "spamcowboy.com",
    "spamex.com", "spamfree24.com", "spamfree24.net", "spamfree24.org",
    "spamfighter.com", "spamhole.com", "spamify.com", "spamjab.com",
    "spam.la", "spammotel.com", "spamspot.com", "spamthis.co.uk",
    "spamwc.de", "spamwp.com", "spam.xyz", "spam.ze.tc"
}

# ── Offline breach demo DB ─────────────────────────────────────────
DEMO_BREACH_DUMP = {
    "john@example.com": ["DemoLeak2022"],
    "alice@sample.net": ["OldBreach2019", "AnotherLeak2021"],
    "test@demo.com": ["TestBreach2023"],
    "admin@example.org": ["AdminLeak2020", "DataBreach2022"]
}

BLACKLIST_ZONES = ["multi.surbl.org", "zen.spamhaus.org", "bl.spamcop.net"]
HEADERS = {"User-Agent": "MailXtract/4.2"}

# ── Helper functions ────────────────────────────────────────────────
def rfc_validate(email: str) -> bool:
    """Validate email format using RFC standard"""
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email))

def split_email(email: str):
    """Split email into local part and domain"""
    parts = email.split("@")
    return parts[0], parts[1].lower()

def qdns(domain: str, rtype: str):
    """Query DNS records"""
    try:
        res = dns.resolver.Resolver()
        res.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']  # Google, Cloudflare, Quad9
        res.timeout = 5
        res.lifetime = 6
        return [r.to_text().strip('"') for r in res.resolve(domain, rtype)]
    except:
        return None

def get_ip(domain: str):
    """Get IP address for domain"""
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def dnssec(domain: str) -> bool:
    """Check if DNSSEC is enabled"""
    return bool(qdns(domain, "DNSKEY"))

def bl_check(domain: str):
    """Check if domain is blacklisted"""
    for zone in BLACKLIST_ZONES:
        try:
            query = ".".join(reversed(domain.split("."))) + "." + zone
            dns.resolver.resolve(query, "A", lifetime=4)
            return True, zone
        except:
            continue
    return False, None

def geo(ip: str):
    """Get geolocation and organization info for IP"""
    if not ip:
        return None, None
    
    # Primary: ipapi
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6, headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            loc = ", ".join(filter(None, [d.get("city"), d.get("region"), d.get("country_name")])) or "N/A"
            return loc, d.get("org")
    except:
        pass
    
    # Fallback: ipinfo
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=6, headers=HEADERS)
        if r.status_code == 200:
            d = r.json()
            loc = ", ".join(filter(None, [d.get("city"), d.get("region"), d.get("country")])) or "N/A"
            return loc, d.get("org")
    except:
        pass
    
    # Second fallback: freegeoip
    try:
        r = requests.get(f"https://freegeoip.app/json/{ip}", timeout=6)
        if r.status_code == 200:
            d = r.json()
            loc = ", ".join(filter(None, [d.get("city"), d.get("region_name"), d.get("country_name")])) or "N/A"
            return loc, None
    except:
        pass
    
    return None, None

def spf_dmarc(domain: str):
    """Get SPF and DMARC records"""
    spf = "Not found"
    dmarc = "Not found"
    
    txt_records = qdns(domain, "TXT") or []
    for rec in txt_records:
        if "v=spf" in rec.lower():
            spf = rec
            break
    
    dmarc_txt = qdns(f"_dmarc.{domain}", "TXT") or []
    if dmarc_txt:
        dmarc = dmarc_txt[0]
    
    return spf, dmarc

def mx(domain: str):
    """Get MX records"""
    return qdns(domain, "MX") or []

def grav(email: str):
    """Check Gravatar existence"""
    url = f"https://www.gravatar.com/avatar/{md5(email.lower().encode()).hexdigest()}?d=404"
    try:
        found = requests.get(url, timeout=6).status_code == 200
        return found, url
    except:
        return False, url

def who(domain: str):
    """Get WHOIS information"""
    try:
        return whois.whois(domain)
    except:
        return None

def clean_date(dt):
    """Clean datetime objects"""
    if isinstance(dt, list):
        dt = dt[0]
    return dt.date() if hasattr(dt, "date") else dt

def age(dt):
    """Calculate domain age in years"""
    try:
        if isinstance(dt, list):
            dt = dt[0]
        if dt:
            return datetime.now(timezone.utc).year - dt.year
        return "Unknown"
    except:
        return "Unknown"

def is_disposable(domain: str) -> bool:
    """Check if domain is disposable"""
    return domain in DISPOSABLE_DOMAINS

def check_breaches(email: str):
    """Check if email appears in known breaches"""
    # In production, use Have I Been Pwned API
    # For demo, use local database
    breaches = DEMO_BREACH_DUMP.get(email.lower(), [])
    
    # Also check HIBP API (optional)
    try:
        # HIBP API v3 (no API key required for email check)
        response = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers={"hibp-api-key": ""},  # Optional key for higher rate limits
            timeout=10
        )
        if response.status_code == 200:
            hibp_data = response.json()
            for breach in hibp_data:
                breach_name = breach.get("Name", "Unknown")
                if breach_name not in breaches:
                    breaches.append(breach_name)
    except:
        pass  # Silent fail for HIBP
    
    return breaches

# ── Main API endpoint ──────────────────────────────────────────────
@app.route('/api/scan', methods=['GET', 'POST'])
def scan_email():
    """Main API endpoint to scan email information"""
    if request.method == 'GET':
        email = request.args.get('email', '').strip()
    else:
        email = request.json.get('email', '').strip() if request.json else ''
        if not email:
            email = request.form.get('email', '').strip()
    
    if not email:
        return jsonify({
            "error": "Email parameter is required",
            "usage": "/api/scan?email=example@domain.com"
        }), 400
    
    if not rfc_validate(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    local_part, domain = split_email(email)
    ip_address = get_ip(domain)
    mx_records = mx(domain)
    spf, dmarc = spf_dmarc(domain)
    is_disp = is_disposable(domain)
    dnssec_enabled = dnssec(domain)
    is_blacklisted, blacklist_zone = bl_check(domain)
    location, organization = geo(ip_address) if ip_address else (None, None)
    has_gravatar, gravatar_url = grav(email)
    whois_data = who(domain)
    breaches = check_breaches(email)
    
    # Prepare domain age info
    domain_age = "Unknown"
    if whois_data and hasattr(whois_data, 'creation_date'):
        domain_age = age(whois_data.creation_date)
    
    # Prepare response
    result = {
        "email": email,
        "local_part": local_part,
        "domain": domain,
        "valid_format": True,
        "disposable": is_disp,
        "ip_address": ip_address,
        "location": location,
        "organization": organization,
        "mx_records": mx_records,
        "spf_record": spf,
        "dmarc_record": dmarc,
        "dnssec_enabled": dnssec_enabled,
        "blacklisted": is_blacklisted,
        "blacklist_zone": blacklist_zone if is_blacklisted else None,
        "gravatar": has_gravatar,
        "gravatar_url": gravatar_url,
        "domain_age_years": domain_age,
        "breaches": breaches if breaches else [],
        "breach_count": len(breaches) if breaches else 0,
        "breach_found": bool(breaches)
    }
    
    # Add WHOIS info if available
    if whois_data:
        result["whois"] = {
            "registrar": whois_data.registrar if hasattr(whois_data, 'registrar') else None,
            "creation_date": str(whois_data.creation_date) if hasattr(whois_data, 'creation_date') else None,
            "expiration_date": str(whois_data.expiration_date) if hasattr(whois_data, 'expiration_date') else None,
            "name_servers": whois_data.name_servers if hasattr(whois_data, 'name_servers') else None
        }
    
    return jsonify(result)

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "WORKING",
        "service": "EMAIL API v1.0",
        "owner": "ANSH TIWARI",
        "channl": "https://t.me/premium_dark_33"
    })

@app.route('/', methods=['GET'])
def index():
    """Root endpoint with API info"""
    return jsonify({
      "status": "WORKING",
        "service": "EMAIL API v1.0",
        "owner": "ANSH TIWARI",
        "channl": "https://t.me/premium_dark_33"
        "endpoints": {
            "scan": "/api/scan?email=example@domain.com",
            "health": "/api/health"
        },
        "methods": ["GET", "POST"],
        "features": [
            "Email validation",
            "Domain analysis",
            "IP geolocation",
            "MX records",
            "SPF/DMARC checks",
            "DNS lookup",
            "Blacklist detection",
            "Breach checking",
            "Gravatar detection",
            "WHOIS information",
            "Disposable email detection"
        ]
    })

# ── For local development ──────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
