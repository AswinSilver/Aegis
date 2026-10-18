from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


_URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})(?![A-Fa-f0-9])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.%]+(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _unique(values: list[str], lower: bool = False) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip().strip(".,;:)]}>")
        key = cleaned.lower() if lower else cleaned
        if cleaned and key not in seen:
            seen.add(key)
            result.append(cleaned.lower() if lower else cleaned)
    return result


def extract_iocs(text: str) -> dict:
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    urls = _unique([match.group(0) for match in _URL_RE.finditer(text)])
    emails = _unique(_EMAIL_RE.findall(text), lower=True)
    hashes = _HASH_RE.findall(text)
    ip_values: list[str] = []
    for candidate in _IPV4_RE.findall(text) + _IPV6_RE.findall(text):
        candidate = candidate.strip("[]")
        try:
            ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            continue
        ip_values.append(candidate)

    domains: list[str] = []
    for candidate in _DOMAIN_RE.findall(text):
        candidate = candidate.rstrip(".").lower()
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        domains.append(candidate)
    for url in urls:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            hostname = None
        if hostname:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                domains.append(hostname.lower().rstrip("."))

    typed_hashes = {
        "md5": _unique([value.lower() for value in hashes if len(value) == 32], lower=True),
        "sha1": _unique([value.lower() for value in hashes if len(value) == 40], lower=True),
        "sha256": _unique([value.lower() for value in hashes if len(value) == 64], lower=True),
    }
    result = {
        "urls": _unique(urls),
        "ipv4": _unique([value for value in ip_values if "." in value]),
        "ipv6": _unique([value for value in ip_values if ":" in value], lower=True),
        "domains": _unique(domains, lower=True),
        "emails": emails,
        "hashes": typed_hashes,
        "cves": _unique([value.upper() for value in _CVE_RE.findall(text)], lower=False),
    }
    result["counts"] = {
        key: (sum(len(values) for values in value.values()) if key == "hashes" else len(value))
        for key, value in result.items()
        if key != "counts"
    }
    result["observations"] = [
        {
            "source": "local.regex_and_stdlib",
            "explanation": "Indicators were extracted locally with deterministic regular expressions and IP validation; no external lookup was performed.",
        }
    ]
    return result
