from __future__ import annotations

import os
import re
from typing import Any

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def nvd_configured() -> bool:
    # NVD's public endpoint does not require an API key.  It is enabled by
    # default so the application remains useful without paid services; set
    # NVD_ENABLED=0 to disable network access explicitly.
    return os.getenv("NVD_ENABLED", "1").lower() not in {"0", "false", "no", "off"}


def _endpoint() -> str:
    return os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")


def _request(params: dict[str, Any]) -> tuple[int, dict]:
    if httpx is None:
        raise RuntimeError("httpx is not installed")
    timeout = float(os.getenv("EXTERNAL_REQUEST_TIMEOUT_SECONDS", "5"))
    headers = {"apiKey": os.getenv("NVD_API_KEY", "").strip()} if os.getenv("NVD_API_KEY", "").strip() else {}
    with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as client:
        response = client.get(_endpoint(), params=params, headers=headers)
    try:
        payload = response.json()
    except Exception:
        payload = {}
    return response.status_code, payload if isinstance(payload, dict) else {}


def _cvss(vulnerability: dict) -> tuple[float | None, str | None]:
    metrics = vulnerability.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            first = entries[0]
            data = first.get("cvssData") or {}
            return data.get("baseScore"), data.get("baseSeverity") or first.get("baseSeverity")
    return None, None


def normalize_item(item: dict) -> dict:
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
    cve_id = cve.get("id")
    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    description = next((entry.get("value") for entry in descriptions if entry.get("lang") == "en"), None)
    score, severity = _cvss(cve)
    refs = [entry.get("url") for entry in (cve.get("references") or []) if isinstance(entry, dict) and entry.get("url")]
    return {
        "source": "NVD",
        "id": cve_id,
        "description": description,
        "cvss_score": score,
        "severity": severity,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": refs,
    }


def search(keyword: str | None, cve_id: str | None, page: int, limit: int, severity: str | None = None, published_after: str | None = None, published_before: str | None = None) -> dict:
    if not nvd_configured():
        raise RuntimeError("NVD is not configured")
    params: dict[str, Any] = {"startIndex": (page - 1) * limit, "resultsPerPage": limit}
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id.upper()
    if severity:
        params["cvssV3Severity"] = severity.upper()
    if published_after:
        params["pubStartDate"] = published_after
    if published_before:
        params["pubEndDate"] = published_before
    try:
        status, payload = _request(params)
    except Exception as exc:
        raise ConnectionError("NVD upstream is unavailable") from exc
    if status < 200 or status >= 300:
        raise ConnectionError(f"NVD upstream returned HTTP {status}")
    vulnerabilities = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
    return {
        "source": "NVD",
        "page": page,
        "limit": limit,
        "total": payload.get("totalResults", len(vulnerabilities)),
        "results": [normalize_item(item) for item in vulnerabilities],
        "upstream": {"timestamp": payload.get("timestamp"), "format": payload.get("format")},
    }
