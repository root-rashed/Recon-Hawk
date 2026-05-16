"""
utils/validator.py - Target validation and normalization for ReconHawk.
"""

import re
import socket
from urllib.parse import urlparse


# Regex patterns
IPV4_RE   = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_target(raw: str) -> dict | None:
    """
    Validate and normalise the user-supplied target.

    Returns a dict with:
        raw        – original input
        display    – clean display string
        host       – hostname or IP (no scheme/path)
        base_url   – scheme + host (https://host)
        scheme     – "http" | "https"
        is_ip      – True if IPv4 address
        is_domain  – True if domain/subdomain
    Returns None if the target is invalid.
    """
    raw = raw.strip()

    # Add scheme if missing so urlparse works correctly
    if not raw.startswith(("http://", "https://")):
        raw_with_scheme = f"https://{raw}"
    else:
        raw_with_scheme = raw

    try:
        parsed = urlparse(raw_with_scheme)
    except Exception:
        return None

    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    if not host:
        return None

    is_ip     = bool(IPV4_RE.match(host))
    is_domain = bool(DOMAIN_RE.match(host)) and not is_ip

    if not is_ip and not is_domain:
        return None

    # Validate IPv4 octets
    if is_ip:
        octets = host.split(".")
        if any(int(o) > 255 for o in octets):
            return None

    base_url = f"{scheme}://{host}"
    if parsed.port:
        base_url += f":{parsed.port}"

    # Attempt a basic DNS resolution for domains (non-fatal)
    resolved_ip = None
    if is_domain:
        try:
            resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            pass  # offline / unresolvable – still allow the scan

    return {
        "raw":         raw,
        "display":     host,
        "host":        host,
        "base_url":    base_url,
        "scheme":      scheme,
        "port":        parsed.port,
        "path":        parsed.path or "/",
        "is_ip":       is_ip,
        "is_domain":   is_domain,
        "resolved_ip": resolved_ip,
    }
