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

## 📋 Step-by-Step GitHub Setup

### Step 1 — Create a new GitHub repository

1. Go to [github.com](https://github.com) and log in
2. Click the **"+"** icon (top right) → **"New repository"**
3. Fill in:
   - **Repository name:** `WebVulnScanner`
   - **Description:** `OWASP-based web vulnerability scanner for educational security assessments`
   - **Visibility:** Public *(or Private — your choice)*
   - ✅ Check **"Add a README file"** → *we'll replace it*
4. Click **"Create repository"**

---

### Step 2 — Clone the repository locally

Open your terminal and run:

```bash
git clone https://github.com/YOUR_USERNAME/WebVulnScanner.git
cd WebVulnScanner
```

> Replace `YOUR_USERNAME` with your actual GitHub username.

---

### Step 3 — Add the project files

Copy `scanner.py` and `requirements.txt` into the cloned folder, then replace the auto-generated README:

```bash
# Verify files are in place
ls -la
# Expected output:
# scanner.py
# requirements.txt
# README.md
```

---

### Step 4 — Stage, commit, and push to GitHub

```bash
# Stage all files
git add .

# Commit with a descriptive message
git commit -m "feat: initial release of WebVulnScanner v1.0

- Module 1: Security Headers detection (7 headers)
- Module 2: Reflected XSS via query parameter injection
- Module 3: SQL Injection error-based detection
- Module 4: Open Redirect via common redirect parameters
- Module 5: Sensitive file and directory exposure
- JSON report generation with timestamp"

# Push to GitHub
git push origin main
```

---

### Step 5 — Add Topics & Description on GitHub

1. Go to your repository page on GitHub
2. Click the **⚙️ gear icon** next to "About" (top right of the repo)
3. Add **Description:** `OWASP-based web vulnerability scanner — educational tool`
4. Add **Topics:** `python`, `security`, `owasp`, `penetration-testing`, `vulnerability-scanner`, `cybersecurity`
5. Click **Save changes**

---

### Step 6 — Create a Release (optional but looks professional)

1. On your repo page → click **"Releases"** (right sidebar)
2. Click **"Create a new release"**
3. Tag: `v1.0.0`
4. Title: `WebVulnScanner v1.0.0 — Initial Release`
5. Description:
   ```
   ## 🔴 First release of WebVulnScanner

   ### Features
   - 5-module OWASP vulnerability scanner
   - Reflected XSS detection
   - SQL Injection error-based detection
   - Security headers audit
   - Open redirect testing
   - Sensitive file exposure checks
   - JSON report generation
   ```
6. Click **"Publish release"**

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
