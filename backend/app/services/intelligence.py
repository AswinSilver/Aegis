from __future__ import annotations

import base64
import copy
import ipaddress
import threading
import os
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit
from typing import Any
from time import monotonic

try:  # Optional at runtime; configured integrations report unavailable when absent.
    import httpx
except ImportError:  # pragma: no cover - exercised in minimal installs
    httpx = None


HASH_RE = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?$")
_CACHE_TTL_SECONDS = float(os.getenv("INTELLIGENCE_CACHE_TTL_SECONDS", "900"))
_CACHE: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _private_label(ip: ipaddress._BaseAddress) -> str:
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        return "private"
    return "public"


def _hostname_is_internal(hostname: str) -> bool:
    value = hostname.rstrip(".").lower()
    if value in {"localhost", "localhost.localdomain", "broadcasthost"}:
        return True
    return value.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".test", ".invalid"))


def _resolves_to_private(hostname: str) -> bool:
    """Best-effort destination safety check; failure is not treated as a provider error."""

    if _hostname_is_internal(hostname):
        return True
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(0.5)
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
        finally:
            socket.setdefaulttimeout(old_timeout)
        return any(not ipaddress.ip_address(address.split("%", 1)[0]).is_global for address in addresses)
    except (OSError, ValueError):
        return False


def _validate(kind: str, raw_value: str) -> tuple[str, str, bool, str | None]:
    value = raw_value.strip()
    if not value:
        raise ValueError("indicator is empty")
    if kind == "ip":
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc
        classification = _private_label(parsed)
        return value, classification, classification == "public", None if classification == "public" else "private_or_reserved_destination"
    if kind == "hash":
        for algorithm, pattern in HASH_RE.items():
            if pattern.fullmatch(value):
                return value.lower(), algorithm, True, None
        raise ValueError("hash must be a hexadecimal MD5, SHA1, or SHA256 value")
    if kind == "domain":
        single_label = re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,251}[A-Za-z0-9])?", value)
        if not DOMAIN_RE.fullmatch(value) and not single_label:
            raise ValueError("invalid domain")
        normalized = value.rstrip(".").lower()
        try:
            parsed = ipaddress.ip_address(normalized)
        except ValueError:
            parsed = None
        if parsed is not None:
            classification = _private_label(parsed)
        elif single_label or _hostname_is_internal(normalized) or _resolves_to_private(normalized):
            classification = "private_internal"
        else:
            classification = "public_domain"
        return normalized, classification, classification == "public_domain", None if classification == "public_domain" else "private_or_internal_destination"
    if kind == "url":
        if any(character.isspace() for character in value):
            raise ValueError("URL cannot contain whitespace")
        try:
            parsed_url = urlsplit(value)
        except ValueError as exc:
            raise ValueError("invalid URL") from exc
        if parsed_url.scheme.lower() not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError("URL must use http or https and include a hostname")
        if parsed_url.username or parsed_url.password:
            raise ValueError("URLs with embedded credentials are not accepted")
        try:
            parsed_url.port
        except ValueError as exc:
            raise ValueError("URL port is invalid") from exc
        hostname = parsed_url.hostname
        try:
            parsed_ip = ipaddress.ip_address(hostname)
        except ValueError:
            parsed_ip = None
        if parsed_ip is not None:
            classification = _private_label(parsed_ip)
        elif _hostname_is_internal(hostname) or _resolves_to_private(hostname):
            classification = "private_internal"
        else:
            classification = "public_url"
        normalized_host = hostname.lower().rstrip(".")
        if ":" in normalized_host and not normalized_host.startswith("["):
            normalized_host = f"[{normalized_host}]"
        port_suffix = f":{parsed_url.port}" if parsed_url.port is not None and not ((parsed_url.scheme.lower() == "http" and parsed_url.port == 80) or (parsed_url.scheme.lower() == "https" and parsed_url.port == 443)) else ""
        normalized = urlunsplit((parsed_url.scheme.lower(), f"{normalized_host}{port_suffix}", parsed_url.path or "/", parsed_url.query, parsed_url.fragment))
        return normalized, classification, classification == "public_url", None if classification == "public_url" else "private_or_internal_destination"
    raise ValueError("unsupported intelligence type")


def _provider_result(source: str, status: str, verdict: str, explanation: str, **extra: Any) -> dict:
    result = {
        "source": source,
        "status": status,
        "verdict": verdict,
        "explanation": explanation,
    }
    result.update(extra)
    return result


def _safe_json(response: Any) -> dict:
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _http_request(method: str, url: str, *, headers: dict[str, str] | None = None, params: dict[str, Any] | None = None, data: dict[str, Any] | None = None) -> tuple[int, dict]:
    if httpx is None:
        raise RuntimeError("httpx is not installed")
    timeout = float(os.getenv("EXTERNAL_REQUEST_TIMEOUT_SECONDS", "5"))
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        response = client.request(method, url, headers=headers, params=params, data=data)
    return response.status_code, _safe_json(response)


def _abuseipdb(value: str, key: str) -> dict:
    try:
        status, payload = _http_request(
            "GET",
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": "90"},
        )
    except Exception:
        return _provider_result("abuseipdb", "unavailable", "unavailable", "AbuseIPDB could not be reached within the configured timeout.")
    if status == 404:
        return _provider_result("abuseipdb", "no_result", "no_result", "AbuseIPDB has no result for this indicator.")
    if status < 200 or status >= 300:
        return _provider_result("abuseipdb", "unavailable", "unavailable", f"AbuseIPDB returned HTTP {status}.")
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
    score = data.get("abuseConfidenceScore")
    verdict = "suspicious" if isinstance(score, (int, float)) and score > 0 else "no_result"
    return _provider_result(
        "abuseipdb",
        "result" if verdict != "no_result" else "no_result",
        verdict,
        "AbuseIPDB supplied a source-attributed abuse confidence result." if verdict != "no_result" else "AbuseIPDB returned no positive abuse signal.",
        abuse_confidence_score=score,
        total_reports=data.get("totalReports"),
        last_reported_at=data.get("lastReportedAt"),
    )


def _virustotal(kind: str, value: str, key: str) -> dict:
    if kind == "ip":
        path = f"ip_addresses/{value}"
    elif kind == "domain":
        path = f"domains/{value}"
    elif kind == "hash":
        path = f"files/{value}"
    else:
        encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        path = f"urls/{encoded}"
    try:
        status, payload = _http_request(
            "GET",
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": key, "Accept": "application/json"},
        )
    except Exception:
        return _provider_result("virustotal", "unavailable", "unavailable", "VirusTotal could not be reached within the configured timeout.")
    if status == 404:
        return _provider_result("virustotal", "no_result", "no_result", "VirusTotal has no result for this indicator.")
    if status < 200 or status >= 300:
        return _provider_result("virustotal", "unavailable", "unavailable", f"VirusTotal returned HTTP {status}.")
    attributes = ((payload.get("data") or {}).get("attributes") or {}) if isinstance(payload.get("data"), dict) else {}
    stats = attributes.get("last_analysis_stats") if isinstance(attributes.get("last_analysis_stats"), dict) else {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    verdict = "malicious" if malicious else "suspicious" if suspicious else "no_result"
    return _provider_result(
        "virustotal",
        "result" if verdict != "no_result" else "no_result",
        verdict,
        "VirusTotal supplied source-attributed analysis statistics." if verdict != "no_result" else "VirusTotal returned no positive detection signal.",
        last_analysis_stats=stats,
        reputation=attributes.get("reputation"),
    )


def _urlhaus(value: str, url: str) -> dict:
    try:
        status, payload = _http_request("POST", url, data={"url": value})
    except Exception:
        return _provider_result("urlhaus", "unavailable", "unavailable", "URLhaus could not be reached within the configured timeout.")
    if status == 404 or payload.get("query_status") in {"no_results", "invalid_url"}:
        return _provider_result("urlhaus", "no_result", "no_result", "URLhaus has no result for this URL.")
    if status < 200 or status >= 300:
        return _provider_result("urlhaus", "unavailable", "unavailable", f"URLhaus returned HTTP {status}.")
    verdict = "malicious" if payload.get("query_status") == "ok" else "no_result"
    return _provider_result(
        "urlhaus",
        "result" if verdict == "malicious" else "no_result",
        verdict,
        "URLhaus returned a matching URL record." if verdict == "malicious" else "URLhaus returned no result.",
        threat=payload.get("threat"),
        url_status=payload.get("url_status"),
    )


def investigate(kind: str, raw_value: str) -> dict:
    value, classification, allowed_external, block_reason = _validate(kind, raw_value)
    cache_key = (kind, value.casefold())
    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached and cached[0] > monotonic():
            result = copy.deepcopy(cached[1])
            result["cached"] = True
            result["checked_at"] = _now()
            return result
        if cached:
            _CACHE.pop(cache_key, None)
    results: list[dict] = []
    configured: list[str] = []
    if not allowed_external:
        results.append(
            _provider_result(
                "local_validation",
                "blocked",
                "no_result",
                "The indicator is private/internal/reserved; no external provider was contacted.",
            )
        )
    else:
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        urlhaus_url = os.getenv("URLHAUS_API_URL", "").strip()
        if not urlhaus_url and os.getenv("URLHAUS_ENABLED", "").lower() in {"1", "true", "yes"}:
            urlhaus_url = "https://urlhaus-api.abuse.ch/v1/url/"
        if kind == "ip" and abuse_key:
            configured.append("abuseipdb")
            results.append(_abuseipdb(value, abuse_key))
        if vt_key:
            configured.append("virustotal")
            results.append(_virustotal(kind, value, vt_key))
        if kind == "url" and urlhaus_url:
            configured.append("urlhaus")
            results.append(_urlhaus(value, urlhaus_url))
        if not configured:
            results.append(
                _provider_result(
                    "local_validation",
                    "no_result",
                    "no_result",
                    "No external intelligence provider is configured; local validation completed without asserting an absence of risk.",
                )
            )

    priority = {"malicious": 4, "suspicious": 3, "no_result": 2, "unavailable": 1}
    verdict = max((item["verdict"] for item in results), key=lambda item: priority.get(item, 0), default="no_result")
    result = {
        "indicator_type": kind,
        "indicator": value,
        "classification": classification,
        "algorithm": classification if kind == "hash" else None,
        "valid": True,
        "externally_queried": bool(configured) and allowed_external,
        "configured_providers": configured,
        "verdict": verdict,
        "checked_at": _now(),
        "results": results,
        "findings": results,
        "source_attribution": [item["source"] for item in results],
        "explanation": (
            "Results are source-attributed and no provider response was converted into an unsupported absence-of-risk verdict."
            if verdict in {"no_result", "unavailable"}
            else "At least one configured provider returned a positive source-attributed signal."
        ),
        "blocked_reason": block_reason,
        "cached": False,
    }
    with _CACHE_LOCK:
        _CACHE[cache_key] = (monotonic() + max(_CACHE_TTL_SECONDS, 0), copy.deepcopy(result))
    return result
