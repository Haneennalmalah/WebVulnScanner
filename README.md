# 🔴 WebVulnScanner

> An OWASP-based command-line web vulnerability scanner built in Python for educational and authorized security assessments.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Purpose-Educational-orange)

---

## ⚠️ Disclaimer

This tool is built **strictly for educational purposes and authorized penetration testing only**.  
Never scan systems you do not own or have explicit written permission to test.  
Unauthorized scanning is illegal and unethical.

---

## 📌 What This Tool Does

WebVulnScanner automates the detection of 5 common web vulnerability categories defined by [OWASP](https://owasp.org/www-project-top-ten/):

| Module | Vulnerability | OWASP Category |
|--------|--------------|----------------|
| 1 | Missing Security Headers | A05 - Security Misconfiguration |
| 2 | Cross-Site Scripting (XSS) | A03 - Injection |
| 3 | SQL Injection (Error-based) | A03 - Injection |
| 4 | Open Redirect | A01 - Broken Access Control |
| 5 | Sensitive File Exposure | A05 - Security Misconfiguration |

---

## 🗂️ Project Structure

```
WebVulnScanner/
├── scanner.py          # Main scanner script
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── scan_report_*.json  # Auto-generated reports (after running)
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

---

## 💻 Installation & Usage

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the scanner

```bash
python scanner.py <target_url>
```

### Examples

```bash
# Scan a URL with query parameters (best for XSS/SQLi testing)
python scanner.py "https://testphp.vulnweb.com/listproducts.php?cat=1"

# Scan a base URL (good for headers, sensitive files, redirects)
python scanner.py "https://example.com"
```

> 💡 **Safe test targets (legal!):**
> - `http://testphp.vulnweb.com` — Acunetix's intentionally vulnerable site
> - `http://dvwa.local` — DVWA running locally

---

## 📊 Sample Output

```
[*] Target: https://testphp.vulnweb.com/listproducts.php?cat=1
[*] Starting scan...

─────────────────────────────────────────────────────
  MODULE 1: Security Headers Check
─────────────────────────────────────────────────────
[!] VULNERABLE: Missing 'Content-Security-Policy' — Prevents XSS & data injection attacks
[!] VULNERABLE: Missing 'Strict-Transport-Security' — Enforces HTTPS connections (HSTS)
[✓] X-Content-Type-Options — present

  Header Security Score: 28%

─────────────────────────────────────────────────────
  MODULE 2: Cross-Site Scripting (XSS)
─────────────────────────────────────────────────────
[!] VULNERABLE: Reflected XSS in param 'cat' with payload: <script>alert('XSS')</script>

─────────────────────────────────────────────────────
  MODULE 3: SQL Injection
─────────────────────────────────────────────────────
[!] VULNERABLE: SQL error in param 'cat' — 'you have an error in your sql syntax' detected

═══════════════════════════════════════════════════════
  SCAN COMPLETE — 14:32:10
═══════════════════════════════════════════════════════
  Target      : https://testphp.vulnweb.com/...
  Total Issues: 7
  Report saved: scan_report_2025-01-15_14-32-10.json
```

---

## 📄 JSON Report Format

Each scan auto-generates a timestamped JSON report:

```json
{
  "tool": "WebVulnScanner v1.0",
  "target": "https://target.com/page?id=1",
  "scan_time": "2025-01-15T14:32:10",
  "summary": {
    "missing_headers": 5,
    "xss_findings": 1,
    "sqli_findings": 1,
    "open_redirect_findings": 0,
    "sensitive_files_found": 2
  },
  "details": { ... }
}
```

---

## 🧠 Vulnerability Explanations

### 1. Missing Security Headers
HTTP response headers that browsers enforce to prevent common attacks.  
**Impact:** Without CSP, attackers can inject malicious scripts. Without HSTS, connections can be downgraded to HTTP.

### 2. Cross-Site Scripting (XSS)
Malicious scripts injected into web pages viewed by other users.  
**Detection method:** Inject payloads into URL parameters and check if they're reflected in the response body.

### 3. SQL Injection
Malicious SQL statements inserted into query fields.  
**Detection method:** Error-based — inject payloads that trigger database error messages.

### 4. Open Redirect
Redirecting users to attacker-controlled URLs via unsanitized redirect parameters.  
**Impact:** Phishing attacks, stealing tokens after OAuth flows.

### 5. Sensitive File Exposure
Publicly accessible config files, backups, or admin panels.  
**Examples:** `.env` files containing DB passwords, `.git/config` exposing source code.

---

## 🔧 Extending the Tool

Want to add more checks? The scanner is modular — each test is a standalone function.

```python
# Example: Add a new module at the bottom of scanner.py
def check_cors_misconfiguration(url):
    r = safe_get(url, headers={"Origin": "https://evil.com"})
    if r and r.headers.get("Access-Control-Allow-Origin") == "*":
        log_vuln("Wildcard CORS policy detected")
```

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

---

## 📝 License

MIT License — free to use for educational and authorized testing purposes.
