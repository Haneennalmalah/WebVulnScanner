#!/usr/bin/env python3
"""
WebVulnScanner - OWASP-based Web Vulnerability Scanner
Author: Security Researcher
Version: 1.0.0
"""

import requests
import sys
import json
import re
import time
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

TIMEOUT = 10
HEADERS = {
    "User-Agent": "WebVulnScanner/1.0 (Educational Security Tool)"
}

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "';alert('XSS');//",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "pg_query",
    "sqlite3",
    "syntax error",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Prevents XSS & data injection attacks",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Controls browser feature access",
    "X-XSS-Protection": "Enables browser XSS filter (legacy)",
}

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "goto", "returnUrl", "redirect_to", "dest"]


# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

def print_banner():
    print(Fore.RED + r"""
 __      __      _    _   _____                                
 \ \    / /     | |  | | / ____|                               
  \ \  / /__ _ _| |  | || (___   ___ __ _ _ __  _ __   ___ _ __ 
   \ \/ / _` | | |  | | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \  / (_| | | |__| | ____) | (_| (_| | | | | | | |  __/ |   
     \/ \__,_|_|\____/ |_____/ \___\__,_|_| |_|_| |_|\___|_|   
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + "  OWASP Web Vulnerability Scanner v1.0 | Educational Use Only\n" + Style.RESET_ALL)


# ─────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────

def log_info(msg):    print(Fore.CYAN    + f"[*] {msg}" + Style.RESET_ALL)
def log_ok(msg):      print(Fore.GREEN   + f"[✓] {msg}" + Style.RESET_ALL)
def log_vuln(msg):    print(Fore.RED     + f"[!] VULNERABLE: {msg}" + Style.RESET_ALL)
def log_warn(msg):    print(Fore.YELLOW  + f"[~] {msg}" + Style.RESET_ALL)
def log_skip(msg):    print(Fore.WHITE   + f"[-] {msg}" + Style.RESET_ALL)


def safe_get(url, params=None, allow_redirects=True):
    try:
        r = requests.get(url, params=params, headers=HEADERS,
                         timeout=TIMEOUT, allow_redirects=allow_redirects, verify=False)
        return r
    except requests.exceptions.RequestException as e:
        log_warn(f"Request failed: {e}")
        return None


def inject_payload_in_url(url, payload):
    """Replace every query param value with the payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    injected_urls = []
    for key in params:
        new_params = {k: v[0] for k, v in params.items()}
        new_params[key] = payload
        new_query = urlencode(new_params)
        new_parsed = parsed._replace(query=new_query)
        injected_urls.append((key, urlunparse(new_parsed)))
    return injected_urls


# ─────────────────────────────────────────────
#  MODULE 1 — Security Headers
# ─────────────────────────────────────────────

def check_security_headers(url):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  MODULE 1: Security Headers Check")
    print(f"{'─'*55}{Style.RESET_ALL}")

    results = {"missing": [], "present": []}
    r = safe_get(url)
    if not r:
        log_warn("Could not reach target for header check.")
        return results

    for header, description in SECURITY_HEADERS.items():
        if header.lower() in [h.lower() for h in r.headers]:
            log_ok(f"{header} — present")
            results["present"].append(header)
        else:
            log_vuln(f"Missing '{header}' — {description}")
            results["missing"].append(header)

    score = len(results["present"]) / len(SECURITY_HEADERS) * 100
    color = Fore.GREEN if score >= 70 else (Fore.YELLOW if score >= 40 else Fore.RED)
    print(color + f"\n  Header Security Score: {score:.0f}%\n" + Style.RESET_ALL)
    return results


# ─────────────────────────────────────────────
#  MODULE 2 — XSS Detection
# ─────────────────────────────────────────────

def check_xss(url):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  MODULE 2: Cross-Site Scripting (XSS)")
    print(f"{'─'*55}{Style.RESET_ALL}")

    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        log_skip("No query parameters found — skipping XSS test.")
        return findings

    for payload in XSS_PAYLOADS:
        injected = inject_payload_in_url(url, payload)
        for param, injected_url in injected:
            r = safe_get(injected_url)
            if r and payload in r.text:
                log_vuln(f"Reflected XSS in param '{param}' with payload: {payload[:40]}")
                findings.append({"param": param, "payload": payload, "url": injected_url})
                break  # one confirmed finding per payload is enough
            else:
                log_info(f"Testing XSS in '{param}' — not reflected")

    if not findings:
        log_ok("No reflected XSS detected in query parameters.")
    return findings


# ─────────────────────────────────────────────
#  MODULE 3 — SQL Injection
# ─────────────────────────────────────────────

def check_sqli(url):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  MODULE 3: SQL Injection")
    print(f"{'─'*55}{Style.RESET_ALL}")

    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        log_skip("No query parameters found — skipping SQLi test.")
        return findings

    for payload in SQLI_PAYLOADS:
        injected = inject_payload_in_url(url, payload)
        for param, injected_url in injected:
            r = safe_get(injected_url)
            if r:
                body_lower = r.text.lower()
                for error in SQLI_ERRORS:
                    if error in body_lower:
                        log_vuln(f"SQL error in param '{param}' — '{error}' detected")
                        findings.append({"param": param, "payload": payload, "error": error})
                        break
                else:
                    log_info(f"Testing SQLi in '{param}' — no error signature")

    if not findings:
        log_ok("No SQL injection error signatures detected.")
    return findings


# ─────────────────────────────────────────────
#  MODULE 4 — Open Redirect
# ─────────────────────────────────────────────

def check_open_redirect(url):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  MODULE 4: Open Redirect")
    print(f"{'─'*55}{Style.RESET_ALL}")

    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for param in REDIRECT_PARAMS:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = f"{base}?{param}={payload}"
            r = safe_get(test_url, allow_redirects=False)
            if r and r.status_code in (301, 302, 303, 307, 308):
                location = r.headers.get("Location", "")
                if "evil.com" in location or location.startswith("//"):
                    log_vuln(f"Open redirect via param '{param}' → {location}")
                    findings.append({"param": param, "payload": payload, "location": location})
                else:
                    log_info(f"Redirect on '{param}' but to safe location: {location[:50]}")
            else:
                log_skip(f"No redirect on param '{param}' with payload '{payload[:30]}'")

    if not findings:
        log_ok("No open redirect vulnerabilities detected.")
    return findings


# ─────────────────────────────────────────────
#  MODULE 5 — Sensitive File Exposure
# ─────────────────────────────────────────────

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/admin", "/admin/login", "/phpmyadmin", "/backup.zip",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
    "/.DS_Store", "/web.config", "/debug", "/api/v1/users",
]

def check_sensitive_files(url):
    print(f"\n{Fore.MAGENTA}{'─'*55}")
    print(f"  MODULE 5: Sensitive File & Directory Exposure")
    print(f"{'─'*55}{Style.RESET_ALL}")

    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for path in SENSITIVE_PATHS:
        test_url = urljoin(base, path)
        r = safe_get(test_url)
        if r and r.status_code == 200:
            log_vuln(f"Exposed: {test_url} (HTTP {r.status_code})")
            findings.append({"path": path, "url": test_url, "status": r.status_code})
        elif r and r.status_code in (401, 403):
            log_warn(f"Protected (but exists): {test_url} (HTTP {r.status_code})")
        else:
            log_skip(f"Not found: {path}")

    if not findings:
        log_ok("No obviously exposed sensitive files detected.")
    return findings


# ─────────────────────────────────────────────
#  REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(url, results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_report_{timestamp}.json"

    report = {
        "tool": "WebVulnScanner v1.0",
        "target": url,
        "scan_time": datetime.now().isoformat(),
        "summary": {
            "missing_headers": len(results["headers"].get("missing", [])),
            "xss_findings": len(results["xss"]),
            "sqli_findings": len(results["sqli"]),
            "open_redirect_findings": len(results["open_redirect"]),
            "sensitive_files_found": len(results["sensitive_files"]),
        },
        "details": results,
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    total = sum(report["summary"].values())
    print(f"\n{Fore.CYAN}{'═'*55}")
    print(f"  SCAN COMPLETE — {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'═'*55}{Style.RESET_ALL}")
    print(f"  Target      : {url}")
    print(f"  Total Issues: {Fore.RED}{total}{Style.RESET_ALL}")
    print(f"  Report saved: {Fore.GREEN}{filename}{Style.RESET_ALL}\n")

    return filename


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()

    if len(sys.argv) < 2:
        print(f"Usage: python scanner.py <target_url>")
        print(f"Example: python scanner.py https://testphp.vulnweb.com/listproducts.php?cat=1")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = "https://" + url

    log_info(f"Target: {url}")
    log_info("Starting scan...\n")

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    results = {
        "headers":       check_security_headers(url),
        "xss":           check_xss(url),
        "sqli":          check_sqli(url),
        "open_redirect": check_open_redirect(url),
        "sensitive_files": check_sensitive_files(url),
    }

    generate_report(url, results)


if __name__ == "__main__":
    main()
