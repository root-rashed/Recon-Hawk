"""
modules/crawler.py - Web crawler module for ReconHawk.

Performs:
  - Recursive crawling up to configurable depth
  - URL and endpoint discovery
  - JavaScript file extraction
  - Parameter extraction (query strings, form inputs, JS variables)
  - Interesting path detection (admin panels, config files, etc.)
  - Smart deduplication
  - Multi-threaded crawling
"""

import re
import time
import urllib3
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

from bs4 import BeautifulSoup

from utils.console import Console
from utils.http_client import build_session, safe_get

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Patterns ──────────────────────────────────────────────────────────────────

JS_URL_PATTERN   = re.compile(r'(?:"|\'|`)(/[^"\'`\s]*|https?://[^"\'`\s]+)(?:"|\'|`)', re.IGNORECASE)
JS_ENDPOINT_PAT  = re.compile(r'(?:fetch|axios|get|post|put|delete|request)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
PARAM_PATTERN    = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]{1,30})\s*[=:]\s*', re.IGNORECASE)
EMAIL_PATTERN    = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
SECRET_PATTERN   = re.compile(
    r'(?:api[_\-]?key|token|secret|password|passwd|pwd|auth|bearer|credential)["\s]*[:=]["\s]*([^\s"\'<>&,;]{8,80})',
    re.IGNORECASE
)

INTERESTING_PATHS = [
    # Admin / management
    "/admin", "/administrator", "/wp-admin", "/manager", "/control",
    "/dashboard", "/panel", "/cpanel", "/webmin",
    # Auth
    "/login", "/logout", "/signin", "/signup", "/register", "/auth",
    "/oauth", "/sso",
    # API
    "/api", "/api/v1", "/api/v2", "/graphql", "/rest",
    "/swagger", "/swagger-ui", "/openapi.json", "/api-docs",
    # Config / debug
    "/.env", "/config", "/configuration", "/settings",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.git/HEAD", "/.svn/entries", "/web.config",
    "/robots.txt", "/sitemap.xml", "/.well-known",
    # Backup / sensitive
    "/backup", "/backup.sql", "/dump.sql", "/db.sql",
    "/passwords.txt", "/credentials.txt",
    # Server status
    "/server-status", "/server-info", "/status", "/health",
    "/metrics", "/actuator", "/actuator/env", "/actuator/health",
    # Upload
    "/upload", "/uploads", "/files", "/attachments", "/media",
]

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".avi", ".pdf", ".zip", ".tar", ".gz",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css",
}


class CrawlerModule:
    """Recursive multi-threaded web crawler."""

    def __init__(self, target: dict, depth: int = 2, threads: int = 10,
                 timeout: int = 10, user_agent: str = "ReconHawk/1.0",
                 rate_limit: float = 0.1):
        self.target     = target
        self.depth      = depth
        self.threads    = threads
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.session    = build_session(user_agent, timeout)
        self.base_host  = target["host"]
        self.base_url   = target["base_url"]

        # Shared state (thread-safe via GIL on sets/lists for our purposes)
        self.visited     = set()
        self.urls        = set()
        self.js_files    = set()
        self.parameters  = set()
        self.forms       = []
        self.emails      = set()
        self.secrets     = []
        self.endpoints   = set()

    # ── Public entry point ────────────────────────────────────────────────────

    def run(self) -> dict:
        Console.info(f"Starting crawler on {self.base_url} (depth={self.depth})")

        # BFS crawl
        self._bfs_crawl()

        # Probe interesting paths
        self._probe_interesting_paths()

        # Analyse collected JS files
        self._analyse_js_files()

        Console.success(f"Crawl complete: {len(self.urls)} URLs | "
                        f"{len(self.js_files)} JS files | "
                        f"{len(self.parameters)} parameters")

        return {
            "urls":              sorted(self.urls),
            "js_files":          sorted(self.js_files),
            "parameters":        sorted(self.parameters),
            "forms":             self.forms,
            "emails":            sorted(self.emails),
            "potential_secrets": self.secrets,
            "endpoints":         sorted(self.endpoints),
            "interesting_paths": self._get_found_interesting(),
        }

    # ── BFS crawl ─────────────────────────────────────────────────────────────

    def _bfs_crawl(self):
        """Breadth-first crawl up to self.depth levels."""
        queue = deque()
        queue.append((self.base_url, 0))
        self.visited.add(self.base_url)

        while queue:
            # Collect this level's batch
            batch = []
            while queue:
                url, depth = queue.popleft()
                if depth <= self.depth:
                    batch.append((url, depth))
                if len(batch) >= self.threads * 5:
                    break

            if not batch:
                break

            with ThreadPoolExecutor(max_workers=self.threads) as exe:
                futures = {exe.submit(self._crawl_url, url, d): (url, d)
                           for url, d in batch}
                for fut in as_completed(futures):
                    child_urls = fut.result()
                    _, parent_depth = futures[fut]
                    next_depth = parent_depth + 1
                    if next_depth <= self.depth:
                        for child in child_urls:
                            if child not in self.visited:
                                self.visited.add(child)
                                queue.append((child, next_depth))

    def _crawl_url(self, url: str, depth: int) -> list:
        """Fetch a URL, extract info, return child URLs."""
        time.sleep(self.rate_limit)
        resp = safe_get(self.session, url, timeout=self.timeout)
        if not resp:
            return []

        self.urls.add(url)
        child_urls = []

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type and "javascript" not in content_type:
            return []

        body = resp.text[:200_000]   # cap at 200 KB

        soup = BeautifulSoup(body, "html.parser")

        # Collect links
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag["href"]
            full = self._resolve_url(url, href)
            if full:
                child_urls.append(full)
                self.urls.add(full)

        # Collect JS files
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            full = self._resolve_url(url, src)
            if full:
                self.js_files.add(full)

        # Inline script analysis
        for tag in soup.find_all("script"):
            if tag.string:
                self._analyse_script(tag.string)

        # Extract query parameters
        parsed = urlparse(url)
        for param in parse_qs(parsed.query).keys():
            self.parameters.add(param)

        # Extract form fields
        for form in soup.find_all("form"):
            self._extract_form(form, url)

        # Extract emails
        for match in EMAIL_PATTERN.findall(body):
            self.emails.add(match)

        return child_urls

    # ── Interesting path probing ──────────────────────────────────────────────

    def _probe_interesting_paths(self):
        Console.info(f"Probing {len(INTERESTING_PATHS)} interesting paths...")
        found = 0

        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            futures = {exe.submit(self._check_path, path): path
                       for path in INTERESTING_PATHS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found += 1
                    Console.success(f"  Interesting path: {result['url']} [{result['status']}]")
                    self.urls.add(result["url"])
                    self.endpoints.add(result["url"])

        Console.success(f"Found {found} interesting paths")

    def _check_path(self, path: str) -> dict | None:
        url  = self.base_url.rstrip("/") + path
        resp = safe_get(self.session, url, timeout=self.timeout,
                        rate_limit=self.rate_limit)
        if resp and resp.status_code not in (404, 410):
            return {"url": url, "status": resp.status_code}
        return None

    def _get_found_interesting(self) -> list:
        """Return INTERESTING_PATHS that appear in collected endpoints."""
        found = []
        for path in INTERESTING_PATHS:
            full = self.base_url.rstrip("/") + path
            if full in self.endpoints or full in self.urls:
                found.append(full)
        return found

    # ── JS analysis ───────────────────────────────────────────────────────────

    def _analyse_js_files(self):
        if not self.js_files:
            return
        Console.info(f"Analysing {len(self.js_files)} JavaScript files...")
        with ThreadPoolExecutor(max_workers=self.threads) as exe:
            list(exe.map(self._fetch_and_analyse_js, self.js_files))

    def _fetch_and_analyse_js(self, url: str):
        resp = safe_get(self.session, url, timeout=self.timeout,
                        rate_limit=self.rate_limit)
        if resp and resp.text:
            self._analyse_script(resp.text)

    def _analyse_script(self, js_code: str):
        """Extract endpoints, parameters, and potential secrets from JS."""
        # Endpoints referenced in fetch/axios/XHR calls
        for match in JS_ENDPOINT_PAT.findall(js_code):
            if match.startswith("/") or match.startswith("http"):
                full = self._resolve_url(self.base_url, match)
                if full:
                    self.endpoints.add(full)

        # URLs embedded as strings
        for match in JS_URL_PATTERN.findall(js_code):
            if any(ext in match for ext in [".json", ".xml", "/api/", "/v1/", "/v2/"]):
                full = self._resolve_url(self.base_url, match)
                if full:
                    self.endpoints.add(full)

        # Variable names as potential parameters
        for match in PARAM_PATTERN.findall(js_code[:20_000]):
            if 2 < len(match) < 30:
                self.parameters.add(match.lower())

        # Potential secrets/API keys
        for match in SECRET_PATTERN.findall(js_code):
            trimmed = match.strip()
            if trimmed and trimmed not in ("true", "false", "null", "undefined"):
                self.secrets.append({"value": trimmed[:60], "truncated": len(trimmed) > 60})

    # ── Form extraction ───────────────────────────────────────────────────────

    def _extract_form(self, form, page_url: str):
        action  = form.get("action", "")
        method  = form.get("method", "GET").upper()
        full    = self._resolve_url(page_url, action) if action else page_url
        fields  = []

        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.get("name") or inp.get("id") or ""
            itype = inp.get("type", "text")
            if name:
                fields.append({"name": name, "type": itype})
                self.parameters.add(name)

        if fields:
            self.forms.append({"action": full, "method": method, "fields": fields})

    # ── URL helpers ───────────────────────────────────────────────────────────

    def _resolve_url(self, base: str, href: str) -> str | None:
        """Resolve href relative to base; return None if off-scope."""
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            return None
        try:
            full   = urljoin(base, href)
            parsed = urlparse(full)
            if parsed.hostname and parsed.hostname != self.base_host:
                return None  # off-scope
            # Drop ignored extensions
            path = parsed.path.lower()
            if any(path.endswith(ext) for ext in IGNORED_EXTENSIONS):
                return None
            # Normalise
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return None
