"""
modules/recon.py - Reconnaissance module for ReconHawk.

Collects:
  - DNS records (A, MX, NS, TXT, CNAME)
  - Subdomain enumeration (wordlist + certificate transparency)
  - HTTP response headers
  - Technology fingerprinting (Wappalyzer-style)
  - Open ports and service banners
  - WHOIS information
"""

import re
import socket
import concurrent.futures
import urllib3
from datetime import datetime

import dns.resolver
import requests

from utils.console import Console
from utils.http_client import build_session, safe_get

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Wordlist for subdomain brute-force ────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "blog", "shop", "portal", "vpn", "ns1", "ns2", "smtp", "pop",
    "imap", "webmail", "secure", "login", "auth", "cdn", "static",
    "img", "media", "assets", "app", "beta", "demo", "docs", "help",
    "support", "status", "monitor", "git", "gitlab", "jenkins", "jira",
    "confluence", "wiki", "internal", "intranet", "dashboard", "panel",
    "backend", "db", "database", "redis", "mysql", "proxy", "gateway",
    "cloud", "s3", "storage", "backup", "old", "new", "v2", "v3",
    "mobile", "m", "wap", "uat", "qa", "sandbox", "preview",
]

# ── Technology fingerprints (header/body patterns) ────────────────────────────
TECH_SIGNATURES = {
    "WordPress":     [r"wp-content", r"wp-includes", r"/xmlrpc\.php"],
    "Joomla":        [r"/components/com_", r"Joomla!", r"joomla"],
    "Drupal":        [r"Drupal", r"/sites/default/files"],
    "Laravel":       [r"laravel_session", r"Laravel"],
    "Django":        [r"csrfmiddlewaretoken", r"Django"],
    "React":         [r"react\.js", r"react-dom", r"__reactFiber"],
    "Angular":       [r"ng-version", r"angular\.js", r"ng-app"],
    "Vue.js":        [r"vue\.js", r"__vue__", r"v-if="],
    "jQuery":        [r"jquery", r"jQuery"],
    "Bootstrap":     [r"bootstrap\.css", r"bootstrap\.js"],
    "Nginx":         [r"nginx"],
    "Apache":        [r"Apache"],
    "IIS":           [r"Microsoft-IIS", r"X-Powered-By: ASP"],
    "PHP":           [r"X-Powered-By: PHP", r"\.php"],
    "ASP.NET":       [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE", r"aspx"],
    "Node.js":       [r"X-Powered-By: Express", r"node\.js"],
    "Ruby on Rails": [r"X-Runtime", r"ruby"],
    "Cloudflare":    [r"CF-Cache-Status", r"cloudflare"],
    "Varnish":       [r"X-Varnish", r"Via: varnish"],
    "Shopify":       [r"shopify", r"cdn\.shopify\.com"],
    "Wix":           [r"wix\.com"],
    "Next.js":       [r"__NEXT_DATA__", r"/_next/"],
    "GraphQL":       [r"graphql", r"__schema"],
}


class ReconModule:
    """Performs all reconnaissance tasks against the target."""

    def __init__(self, target: dict, timeout: int = 10, threads: int = 10,
                 ports: str = "80,443,8080,8443", user_agent: str = "ReconHawk/1.0",
                 rate_limit: float = 0.1):
        self.target      = target
        self.timeout     = timeout
        self.threads     = threads
        self.rate_limit  = rate_limit
        self.ports       = self._parse_ports(ports)
        self.session     = build_session(user_agent, timeout)

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> dict:
        host = self.target["host"]
        Console.info(f"Starting reconnaissance on: {host}")

        results = {
            "dns":         self._dns_enum(host),
            "subdomains":  [],
            "headers":     {},
            "technologies":[],
            "open_ports":  [],
            "whois":       {},
        }

        # Subdomain enumeration (only for real domains, not IPs)
        if self.target["is_domain"]:
            results["subdomains"] = self._enumerate_subdomains(host)
            Console.success(f"Subdomains discovered: {len(results['subdomains'])}")

        # HTTP headers & tech fingerprinting
        http_info = self._probe_http()
        results["headers"]      = http_info.get("headers", {})
        results["technologies"] = http_info.get("technologies", [])
        results["server_info"]  = http_info.get("server_info", {})

        # Port scanning
        results["open_ports"] = self._port_scan(host)
        Console.success(f"Open ports found: {len(results['open_ports'])}")

        # WHOIS (best-effort)
        results["whois"] = self._whois(host)

        return results

    # ── DNS enumeration ───────────────────────────────────────────────────────

    def _dns_enum(self, host: str) -> dict:
        Console.info("Enumerating DNS records...")
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.timeout

        for rtype in record_types:
            try:
                answers = resolver.resolve(host, rtype)
                records[rtype] = [r.to_text() for r in answers]
            except Exception:
                records[rtype] = []

        a_count  = len(records.get("A", []))
        mx_count = len(records.get("MX", []))
        Console.success(f"DNS records: A={a_count}, MX={mx_count}")
        return records

    # ── Subdomain enumeration ─────────────────────────────────────────────────

    def _enumerate_subdomains(self, domain: str) -> list:
        Console.info("Enumerating subdomains (wordlist + crt.sh)...")
        found = set()

        # 1. Wordlist brute-force via DNS
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = {
                exe.submit(self._resolve_sub, f"{sub}.{domain}"): sub
                for sub in SUBDOMAIN_WORDLIST
            }
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    found.add(result)

        # 2. Certificate Transparency (crt.sh)
        crt_subs = self._crtsh(domain)
        found.update(crt_subs)

        subs = sorted(found)
        Console.list_items(subs, label=f"Found {len(subs)} subdomains:", limit=15)
        return subs

    def _resolve_sub(self, fqdn: str) -> str | None:
        """Resolve a single hostname; return it if it resolves."""
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(fqdn)
            return fqdn
        except Exception:
            return None

    def _crtsh(self, domain: str) -> list:
        """Query crt.sh certificate transparency logs."""
        try:
            url  = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data  = resp.json()
                names = set()
                for entry in data:
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(f".{domain}") or name == domain:
                            names.add(name)
                return list(names)
        except Exception:
            pass
        return []

    # ── HTTP probing & technology fingerprinting ──────────────────────────────

    def _probe_http(self) -> dict:
        Console.info("Probing HTTP headers and fingerprinting technologies...")
        base_url = self.target["base_url"]
        result   = {"headers": {}, "technologies": [], "server_info": {}}

        resp = safe_get(self.session, base_url, timeout=self.timeout,
                        rate_limit=self.rate_limit)
        if not resp:
            # Try HTTP fallback
            http_url = base_url.replace("https://", "http://")
            resp     = safe_get(self.session, http_url, timeout=self.timeout)

        if not resp:
            Console.warning("Could not fetch HTTP response")
            return result

        # Capture headers
        result["headers"] = dict(resp.headers)
        result["server_info"] = {
            "status_code":    resp.status_code,
            "final_url":      resp.url,
            "content_length": resp.headers.get("Content-Length", "unknown"),
            "content_type":   resp.headers.get("Content-Type", "unknown"),
        }

        # Technology fingerprinting
        body_text    = resp.text[:50_000]     # first 50 KB
        header_text  = str(resp.headers)
        combined     = body_text + header_text
        detected     = []

        for tech, patterns in TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.append(tech)
                    break

        result["technologies"] = list(set(detected))
        Console.success(f"Technologies detected: {', '.join(detected) if detected else 'None'}")
        return result

    # ── Port scanning ─────────────────────────────────────────────────────────

    def _port_scan(self, host: str) -> list:
        Console.info(f"Scanning {len(self.ports)} ports on {host}...")
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = {exe.submit(self._check_port, host, port): port
                       for port in self.ports}
            for fut in concurrent.futures.as_completed(futures):
                result = fut.result()
                if result:
                    open_ports.append(result)
                    Console.success(f"  Port open: {result['port']}/tcp  ({result['service']})")

        return sorted(open_ports, key=lambda x: x["port"])

    def _check_port(self, host: str, port: int) -> dict | None:
        """Attempt TCP connection; return port info dict or None."""
        service_names = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB",
        }
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                banner = self._grab_banner(host, port)
                return {
                    "port":    port,
                    "service": service_names.get(port, "unknown"),
                    "banner":  banner,
                }
        except Exception:
            pass
        return None

    def _grab_banner(self, host: str, port: int) -> str:
        """Attempt to read a service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:200] if banner else ""
        except Exception:
            return ""

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    def _whois(self, host: str) -> dict:
        """Lightweight WHOIS via python-whois; fail silently."""
        Console.info("Fetching WHOIS information...")
        try:
            import whois as python_whois
            w = python_whois.whois(host)
            return {
                "registrar":        str(w.registrar or ""),
                "creation_date":    str(w.creation_date or ""),
                "expiration_date":  str(w.expiration_date or ""),
                "name_servers":     [str(ns) for ns in (w.name_servers or [])],
                "emails":           list(set(w.emails or [])),
                "org":              str(w.org or ""),
                "country":          str(w.country or ""),
            }
        except Exception:
            return {}

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_ports(ports_str: str) -> list:
        """Parse 'port,port-range,port' into a sorted list of ints."""
        result = set()
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                try:
                    result.update(range(int(start), int(end) + 1))
                except ValueError:
                    pass
            else:
                try:
                    result.add(int(part))
                except ValueError:
                    pass
        return sorted(result)
