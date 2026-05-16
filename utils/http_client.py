"""
utils/http_client.py - Shared HTTP session helper for ReconHawk.
"""

import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_session(user_agent: str, timeout: int = 10, retries: int = 2) -> requests.Session:
    """Return a requests.Session pre-configured with retries and a user-agent."""
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})

    retry_strategy = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.verify = False   # many test targets have self-signed certs

    return session


def safe_get(session: requests.Session, url: str, timeout: int = 10,
             rate_limit: float = 0.0, **kwargs) -> requests.Response | None:
    """GET with exception handling and optional rate-limiting."""
    if rate_limit:
        time.sleep(rate_limit)
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
        return resp
    except Exception:
        return None
