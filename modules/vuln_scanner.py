"""
modules/vuln_scanner.py - Vulnerability scanning module for ReconHawk.

Integrates:
  - Custom HTTP security checks (headers, CORS, auth, etc.)
  - Nikto web server scanner (if installed)
  - Nuclei template scanner (if installed)
"""

import json
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.console import Console
from utils.http_client import build_session, safe_get

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Finding:
    """Represents a single vulnerability finding."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, title: str, severity: str, description: str,
                 url: str = "", evidence: str = "", tool: str = "custom",
                 cwe: str = "", remediation: str = ""):
        self.title       = title
        self.severity    = severity.lower()
        self.description = description
        self.url         = url
        self.evidence    = evidence
        self.tool        = tool
        self.cwe         = cwe
        self.remediation = remediation

    def to_dict(self) -> dict:
        return {
            "title":       self.title,
            "severity":    self.severity,
            "description": self.description,
            "url":         self.url,
            "evidence":    self.evidence,
            "tool":        self.tool,
            "cwe":         self.cwe,
            "remediation": self.remediation,
        }

    def __repr__(self):
        return f"[{self.severity.upper()}] {self.title}"


class VulnScannerModule:
    """Orchestrates all vulnerability scanning activities."""

    def __init__(self, target: dict, timeout: int = 10, threads: int = 10,
                 skip_nikto: bool = False, skip_nuclei: bool = False,
                 rate_limit: float = 0.1):
        self.target      = target
        self.timeout     = timeout
        self.threads     = threads
        self.skip_nikto  = skip_nikto
        self.skip_nuclei = skip_nuclei
        self.rate_limit  = rate_limit
        self.session     = build_session("ReconHawk/1.0", timeout)
        self.findings    = []
        self._lock       = threading.Lock()

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> dict:
        Console.info(f"Starting vulnerability scanning on {self.target['base_url']}")

        tasks = [
            ("Custom Security Checks", self._run_custom_checks),
        ]
        if not self.skip_nikto:
            tasks.append(("Nikto", self._run_nikto))
        if not self.skip_nuclei:
            tasks.append(("Nuclei", self._run_nuclei))

        for name, func in tasks:
            Console.info(f"Running {name}...")
            try:
                func()
            except Exception as e:
                Console.error(f"{name} failed: {e}")

        # Deduplicate and sort findings
        seen   = set()
        unique = []
        for f in self.findings:
            key = f"{f.title}::{f.url}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        unique.sort(key=lambda f: Finding.SEVERITY_ORDER.get(f.severity, 99))

        # Print summary
        self._print_finding_summary(unique)

        # Group by severity
        grouped = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in unique:
            sev = f.severity if f.severity in grouped else "info"
            grouped[sev].append(f.to_dict())

        return grouped

    # ── Custom security checks ────────────────────────────────────────────────

    def _run_custom_checks(self):
        checks = [
            self._check_security_headers,
            self._check_cors,
            self._check_clickjacking,
            self._check_cookie_flags,
            self._check_information_disclosure,
            self._check_http_methods,
            self._check_ssl_tls,
            self._check_directory_listing,
            self._check_default_credentials,
            self._check_open_redirect,
            self._check_sqli_basic,
            self._check_xss_basic,
            self._check_xxe_basic,
            self._check_ssrf_basic,
            self._check_lfi_basic,
        ]

        with ThreadPoolExecutor(max_workers=min(self.threads, len(checks))) as exe:
            futures = [exe.submit(c) for c in checks]
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    Console.error(f"Check error: {e}")

    def _add(self, finding: Finding):
        Console.finding(finding.severity, f"{finding.title}")
        with self._lock:
            self.findings.append(finding)

    # ── Security header checks ────────────────────────────────────────────────

    def _check_security_headers(self):
        resp = safe_get(self.session, self.target["base_url"],
                        timeout=self.timeout, rate_limit=self.rate_limit)
        if not resp:
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}
        url     = self.target["base_url"]

        security_headers = {
            "strict-transport-security": {
                "severity": "medium",
                "title":    "Missing HSTS Header",
                "desc":     "HTTP Strict Transport Security not set; allows SSL stripping.",
                "cwe":      "CWE-319",
                "fix":      "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            },
            "content-security-policy": {
                "severity": "medium",
                "title":    "Missing Content-Security-Policy Header",
                "desc":     "No CSP header; increases XSS risk.",
                "cwe":      "CWE-693",
                "fix":      "Define a restrictive Content-Security-Policy header.",
            },
            "x-frame-options": {
                "severity": "medium",
                "title":    "Missing X-Frame-Options Header",
                "desc":     "Page can be embedded in iframes; clickjacking risk.",
                "cwe":      "CWE-1021",
                "fix":      "Add: X-Frame-Options: DENY or SAMEORIGIN",
            },
            "x-content-type-options": {
                "severity": "low",
                "title":    "Missing X-Content-Type-Options Header",
                "desc":     "Browser may MIME-sniff responses; enables some XSS vectors.",
                "cwe":      "CWE-16",
                "fix":      "Add: X-Content-Type-Options: nosniff",
            },
            "referrer-policy": {
                "severity": "low",
                "title":    "Missing Referrer-Policy Header",
                "desc":     "Referrer data may be leaked to third parties.",
                "fix":      "Add: Referrer-Policy: strict-origin-when-cross-origin",
            },
            "permissions-policy": {
                "severity": "low",
                "title":    "Missing Permissions-Policy Header",
                "desc":     "Browser features not restricted via Permissions-Policy.",
                "fix":      "Define a Permissions-Policy header for your use case.",
            },
        }

        for header, meta in security_headers.items():
            if header not in headers:
                self._add(Finding(
                    title=meta["title"], severity=meta["severity"],
                    description=meta["desc"], url=url,
                    tool="custom", cwe=meta.get("cwe", ""),
                    remediation=meta.get("fix", ""),
                ))

        # Check for server version disclosure
        server = headers.get("server", "")
        if re.search(r'\d+\.\d+', server):
            self._add(Finding(
                title="Server Version Disclosure",
                severity="low",
                description=f"Server header reveals version information: {server}",
                url=url, evidence=f"Server: {server}",
                tool="custom", cwe="CWE-200",
                remediation="Configure server to omit or genericize the Server header.",
            ))

        # X-Powered-By disclosure
        xpb = headers.get("x-powered-by", "")
        if xpb:
            self._add(Finding(
                title="Technology Disclosure via X-Powered-By",
                severity="info",
                description=f"X-Powered-By header reveals backend technology: {xpb}",
                url=url, evidence=f"X-Powered-By: {xpb}",
                tool="custom", cwe="CWE-200",
                remediation="Remove the X-Powered-By header.",
            ))

    # ── CORS check ────────────────────────────────────────────────────────────

    def _check_cors(self):
        url  = self.target["base_url"]
        resp = safe_get(self.session, url, timeout=self.timeout,
                        rate_limit=self.rate_limit,
                        headers={"Origin": "https://evil.example.com"})
        if not resp:
            return

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*":
            self._add(Finding(
                title="Wildcard CORS Policy",
                severity="medium",
                description="Access-Control-Allow-Origin: * allows any origin.",
                url=url, evidence=f"ACAO: {acao}",
                tool="custom", cwe="CWE-942",
                remediation="Restrict CORS to trusted origins only.",
            ))
        elif acao == "https://evil.example.com":
            if acac.lower() == "true":
                self._add(Finding(
                    title="Reflected CORS with Credentials",
                    severity="high",
                    description="Origin reflected in ACAO with credentials allowed; CORS misconfiguration.",
                    url=url, evidence=f"ACAO: {acao}, ACAC: {acac}",
                    tool="custom", cwe="CWE-942",
                    remediation="Validate origins against a whitelist; never reflect arbitrary origins.",
                ))
            else:
                self._add(Finding(
                    title="Reflected CORS Origin",
                    severity="medium",
                    description="Server reflects the supplied Origin value.",
                    url=url, evidence=f"ACAO: {acao}",
                    tool="custom", cwe="CWE-942",
                    remediation="Validate origins against a whitelist.",
                ))

    # ── Clickjacking ──────────────────────────────────────────────────────────

    def _check_clickjacking(self):
        resp = safe_get(self.session, self.target["base_url"], timeout=self.timeout)
        if not resp:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        xfo = headers.get("x-frame-options", "")
        csp = headers.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            self._add(Finding(
                title="Clickjacking Vulnerability",
                severity="medium",
                description="No anti-framing headers found; page may be embeddable in iframes.",
                url=self.target["base_url"],
                tool="custom", cwe="CWE-1021",
                remediation="Set X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            ))

    # ── Cookie security ───────────────────────────────────────────────────────

    def _check_cookie_flags(self):
        resp = safe_get(self.session, self.target["base_url"], timeout=self.timeout)
        if not resp:
            return

        cookies = resp.cookies
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("missing SameSite attribute")

            if issues:
                self._add(Finding(
                    title=f"Insecure Cookie: {cookie.name}",
                    severity="medium",
                    description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                    url=self.target["base_url"],
                    evidence=f"Cookie: {cookie.name}",
                    tool="custom", cwe="CWE-614",
                    remediation="Set Secure; HttpOnly; SameSite=Strict on all session cookies.",
                ))

    # ── Information disclosure ────────────────────────────────────────────────

    def _check_information_disclosure(self):
        sensitive_paths = [
            ("/.env",            "Environment File Exposed",       "critical"),
            ("/.git/HEAD",       "Git Repository Exposed",         "high"),
            ("/phpinfo.php",     "PHP Info Page Exposed",          "high"),
            ("/server-status",   "Apache Server Status Exposed",   "medium"),
            ("/actuator/env",    "Spring Actuator Env Exposed",    "high"),
            ("/actuator/health", "Spring Actuator Health Exposed", "low"),
            ("/web.config",      "Web.config Exposed",             "high"),
            ("/robots.txt",      "Robots.txt Accessible",          "info"),
            ("/sitemap.xml",     "Sitemap Accessible",             "info"),
            ("/.DS_Store",       "macOS .DS_Store Exposed",        "low"),
            ("/crossdomain.xml", "Flash Cross-Domain Policy",      "low"),
            ("/clientaccesspolicy.xml", "Silverlight Policy File", "low"),
        ]

        def probe(path, title, severity):
            url  = self.target["base_url"].rstrip("/") + path
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
            if resp and resp.status_code == 200:
                self._add(Finding(
                    title=title, severity=severity,
                    description=f"Sensitive resource accessible at {url}",
                    url=url, evidence=f"HTTP {resp.status_code}",
                    tool="custom", cwe="CWE-538",
                    remediation=f"Restrict access to {path} via server configuration.",
                ))

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            list(exe.map(lambda t: probe(*t), sensitive_paths))

    # ── HTTP methods ──────────────────────────────────────────────────────────

    def _check_http_methods(self):
        url  = self.target["base_url"]
        try:
            resp = self.session.options(url, timeout=self.timeout, verify=False)
            allow = resp.headers.get("Allow", "")
            dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
            if dangerous:
                self._add(Finding(
                    title="Dangerous HTTP Methods Allowed",
                    severity="medium",
                    description=f"Server allows potentially dangerous methods: {', '.join(dangerous)}",
                    url=url, evidence=f"Allow: {allow}",
                    tool="custom", cwe="CWE-650",
                    remediation="Disable unused/dangerous HTTP methods in server config.",
                ))
            if "TRACE" in allow:
                self._add(Finding(
                    title="HTTP TRACE Method Enabled (XST Risk)",
                    severity="low",
                    description="TRACE method can be used in Cross-Site Tracing (XST) attacks.",
                    url=url,
                    tool="custom", cwe="CWE-16",
                    remediation="Disable TRACE method in server configuration.",
                ))
        except Exception:
            pass

    # ── SSL/TLS checks ────────────────────────────────────────────────────────

    def _check_ssl_tls(self):
        if self.target["scheme"] != "https":
            self._add(Finding(
                title="No HTTPS / Unencrypted Traffic",
                severity="high",
                description="Target does not use HTTPS; all traffic transmitted in cleartext.",
                url=self.target["base_url"],
                tool="custom", cwe="CWE-319",
                remediation="Obtain an SSL/TLS certificate and redirect all HTTP to HTTPS.",
            ))
            return

        # Check if HTTP redirects to HTTPS
        http_url = self.target["base_url"].replace("https://", "http://")
        resp = safe_get(self.session, http_url, timeout=self.timeout)
        if resp and resp.status_code == 200 and "https" not in resp.url:
            self._add(Finding(
                title="HTTP Not Redirected to HTTPS",
                severity="medium",
                description="HTTP endpoint serves content rather than redirecting to HTTPS.",
                url=http_url,
                tool="custom", cwe="CWE-319",
                remediation="Configure 301 redirects from HTTP to HTTPS.",
            ))

    # ── Directory listing ─────────────────────────────────────────────────────

    def _check_directory_listing(self):
        dirs_to_test = ["/images/", "/uploads/", "/files/", "/assets/", "/static/"]
        for path in dirs_to_test:
            url  = self.target["base_url"].rstrip("/") + path
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                if "index of" in body or "parent directory" in body:
                    self._add(Finding(
                        title="Directory Listing Enabled",
                        severity="medium",
                        description=f"Directory listing is enabled at {url}",
                        url=url, evidence="Response contains 'Index of' or 'Parent Directory'",
                        tool="custom", cwe="CWE-548",
                        remediation="Disable directory listing in web server configuration.",
                    ))

    # ── Default credentials ───────────────────────────────────────────────────

    def _check_default_credentials(self):
        admin_paths = ["/admin", "/administrator", "/wp-admin", "/login"]
        creds       = [("admin", "admin"), ("admin", "password"), ("admin", ""),
                       ("root", "root"), ("test", "test")]

        for path in admin_paths:
            url  = self.target["base_url"].rstrip("/") + path
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
            if not resp or resp.status_code == 404:
                continue

            for username, password in creds:
                try:
                    pr = self.session.post(url, timeout=self.timeout, verify=False,
                                           data={"username": username, "password": password,
                                                 "user": username, "pass": password},
                                           allow_redirects=False)
                    if pr.status_code in (301, 302) and "logout" not in pr.text.lower():
                        # Possible successful login (heuristic)
                        self._add(Finding(
                            title="Possible Default Credentials Accepted",
                            severity="critical",
                            description=f"Login at {url} may accept default credentials "
                                        f"({username}:{password}). Manual verification required.",
                            url=url, evidence=f"POST → HTTP {pr.status_code}",
                            tool="custom", cwe="CWE-521",
                            remediation="Change all default credentials immediately.",
                        ))
                        break
                except Exception:
                    pass

    # ── Open redirect ─────────────────────────────────────────────────────────

    def _check_open_redirect(self):
        params  = ["redirect", "url", "next", "return", "returnTo", "goto",
                   "dest", "destination", "redir", "redirect_uri"]
        payload = "https://evil.example.com"

        for param in params:
            url  = f"{self.target['base_url']}?{param}={payload}"
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit, allow_redirects=False)
            if resp and resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.example.com" in location:
                    self._add(Finding(
                        title="Open Redirect Vulnerability",
                        severity="medium",
                        description=f"Parameter '{param}' causes open redirect to arbitrary URLs.",
                        url=url, evidence=f"Location: {location}",
                        tool="custom", cwe="CWE-601",
                        remediation="Validate redirect destinations against an allowlist.",
                    ))
                    return

    # ── Basic injection checks ────────────────────────────────────────────────

    def _check_sqli_basic(self):
        """Probe common parameters for SQL error messages."""
        test_url = f"{self.target['base_url']}?id=1'"
        resp     = safe_get(self.session, test_url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
        if not resp:
            return

        sql_errors = [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"pg_query\(\)",
            r"ora-\d{5}",
            r"microsoft ole db provider for sql server",
            r"sqlite3\.operationalerror",
        ]

        body = resp.text.lower()
        for pattern in sql_errors:
            if re.search(pattern, body, re.IGNORECASE):
                self._add(Finding(
                    title="Potential SQL Injection (Error-Based)",
                    severity="high",
                    description="SQL error message visible in response; possible SQLi.",
                    url=test_url,
                    evidence=re.search(pattern, body, re.IGNORECASE).group(0)[:100],
                    tool="custom", cwe="CWE-89",
                    remediation="Use parameterised queries/prepared statements.",
                ))
                break

    def _check_xss_basic(self):
        """Test a basic reflected XSS payload."""
        payload  = "<script>alert(1)</script>"
        test_url = f"{self.target['base_url']}?q={payload}&search={payload}"
        resp     = safe_get(self.session, test_url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
        if resp and payload in resp.text:
            self._add(Finding(
                title="Potential Reflected XSS",
                severity="high",
                description="XSS payload reflected unencoded in response.",
                url=test_url,
                evidence=f"Payload '{payload}' reflected in body",
                tool="custom", cwe="CWE-79",
                remediation="Encode all user-supplied input before rendering in HTML.",
            ))

    def _check_xxe_basic(self):
        """Send a basic XXE payload to the target."""
        xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>"""
        try:
            resp = self.session.post(
                self.target["base_url"], data=xxe_payload,
                headers={"Content-Type": "application/xml"},
                timeout=self.timeout, verify=False,
            )
            if resp and "root:" in resp.text:
                self._add(Finding(
                    title="XXE Injection – File Disclosure",
                    severity="critical",
                    description="Server processed XXE payload and returned /etc/passwd content.",
                    url=self.target["base_url"],
                    evidence="'root:' present in response",
                    tool="custom", cwe="CWE-611",
                    remediation="Disable external entity processing in XML parsers.",
                ))
        except Exception:
            pass

    def _check_ssrf_basic(self):
        """Check common SSRF parameters."""
        params   = ["url", "path", "host", "dest", "src", "proxy", "image",
                    "load", "fetch", "request", "uri"]
        payload  = "http://127.0.0.1:80/"
        for param in params[:5]:   # limit probes
            url  = f"{self.target['base_url']}?{param}={payload}"
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
            if resp and resp.status_code == 200 and resp.elapsed.total_seconds() > 2:
                self._add(Finding(
                    title="Potential SSRF (Internal Endpoint Reached)",
                    severity="high",
                    description=f"Parameter '{param}' may cause SSRF to internal services.",
                    url=url,
                    tool="custom", cwe="CWE-918",
                    remediation="Validate and whitelist outbound request destinations.",
                ))
                return

    def _check_lfi_basic(self):
        """Test common LFI payloads on path-like parameters."""
        params  = ["file", "page", "path", "include", "template", "doc"]
        payload = "../../../../../../etc/passwd"

        for param in params:
            url  = f"{self.target['base_url']}?{param}={payload}"
            resp = safe_get(self.session, url, timeout=self.timeout,
                            rate_limit=self.rate_limit)
            if resp and "root:" in resp.text:
                self._add(Finding(
                    title="Local File Inclusion (LFI)",
                    severity="critical",
                    description=f"Parameter '{param}' allows reading arbitrary local files.",
                    url=url,
                    evidence="/etc/passwd content in response",
                    tool="custom", cwe="CWE-22",
                    remediation="Validate and sanitize file path inputs; use allowlists.",
                ))
                return

    # ── Nikto integration ─────────────────────────────────────────────────────

    def _run_nikto(self):
        if not shutil.which("nikto"):
            Console.warning("Nikto not found; skipping. Install: sudo apt install nikto")
            return

        Console.info("Running Nikto scan...")
        host    = self.target["host"]
        port    = self.target.get("port") or (443 if self.target["scheme"] == "https" else 80)
        ssl_flag = ["-ssl"] if self.target["scheme"] == "https" else []

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                "nikto", "-h", host, "-p", str(port),
                "-output", tmp_path, "-Format", "txt",
                "-Tuning", "x6789abc",   # broad coverage
                "-timeout", str(self.timeout),
                "-nointeractive",
            ] + ssl_flag

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            with open(tmp_path, "r", errors="ignore") as fh:
                content = fh.read()

            self._parse_nikto_output(content)

        except subprocess.TimeoutExpired:
            Console.warning("Nikto timed out after 5 minutes")
        except Exception as e:
            Console.error(f"Nikto error: {e}")

    def _parse_nikto_output(self, output: str):
        """Extract findings from Nikto plain-text output."""
        url = self.target["base_url"]
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("+") is False:
                continue

            # Rough severity heuristic based on keywords
            lower = line.lower()
            if any(k in lower for k in ["osvdb-", "cve-", "injection", "traversal",
                                        "exec", "shell", "remote", "rce"]):
                severity = "high"
            elif any(k in lower for k in ["outdated", "version", "disclosure",
                                          "sensitive", "backup"]):
                severity = "medium"
            else:
                severity = "info"

            self._add(Finding(
                title=f"Nikto: {line[:80]}",
                severity=severity,
                description=line,
                url=url, tool="nikto",
            ))

    # ── Nuclei integration ────────────────────────────────────────────────────

    def _run_nuclei(self):
        if not shutil.which("nuclei"):
            Console.warning("Nuclei not found; skipping. Install: https://nuclei.projectdiscovery.io/")
            return

        Console.info("Running Nuclei scan...")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        try:
            cmd = [
                "nuclei",
                "-u", self.target["base_url"],
                "-o", tmp_path,
                "-j",                   # JSON output
                "-severity", "info,low,medium,high,critical",
                "-t", "cves/",
                "-t", "vulnerabilities/",
                "-t", "misconfiguration/",
                "-t", "exposures/",
                "-t", "technologies/",
                "-silent",
                "-rate-limit", "10",    # be polite
                "-timeout", str(self.timeout),
            ]

            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            with open(tmp_path, "r", errors="ignore") as fh:
                content = fh.read()

            self._parse_nuclei_output(content)

        except subprocess.TimeoutExpired:
            Console.warning("Nuclei timed out after 10 minutes")
        except Exception as e:
            Console.error(f"Nuclei error: {e}")

    def _parse_nuclei_output(self, output: str):
        """Parse Nuclei JSONL output into Finding objects."""
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info      = data.get("info", {})
            title     = info.get("name", "Nuclei Finding")
            severity  = info.get("severity", "info").lower()
            desc      = info.get("description", "")
            url       = data.get("matched-at", self.target["base_url"])
            template  = data.get("template-id", "")

            # Extract CVE / CWE if available
            class_info = info.get("classification", {})
            cwe_list   = class_info.get("cwe-id", [])
            cwe        = cwe_list[0] if cwe_list else ""

            self._add(Finding(
                title=f"Nuclei: {title}",
                severity=severity,
                description=f"{desc} (template: {template})",
                url=url, tool="nuclei",
                cwe=cwe,
            ))

    # ── Summary ───────────────────────────────────────────────────────────────

    def _print_finding_summary(self, findings: list):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        Console.info("Vulnerability scan summary:")
        for sev, count in counts.items():
            if count:
                Console.finding(sev, f"{sev.capitalize()}: {count}")
