from __future__ import annotations

from datetime import datetime, timezone

from backend.app.services import intelligence, vulnerabilities
from backend.app.services.ioc import extract_iocs
from backend.app.services.logs import analyze_logs
from backend.app.services.rules import explain_condition


def test_ioc_extraction_deduplicates_and_classifies_hashes():
    result = extract_iocs(
        "https://example.test/path https://example.test/path 203.0.113.9 "
        + "a" * 32
        + " "
        + "b" * 64
    )
    assert result["urls"] == ["https://example.test/path"]
    assert result["ipv4"] == ["203.0.113.9"]
    assert result["hashes"]["md5"] == ["a" * 32]
    assert result["hashes"]["sha256"] == ["b" * 64]


def test_log_parser_has_explicit_observations():
    result = analyze_logs(
        '[{"timestamp":"2025-01-01T00:00:00Z","source":"gw","event_type":"login","status":"failed"},'
        '{"timestamp":"2025-01-01T00:01:00Z","source":"gw","event_type":"login","status":"failed"}]'
    )
    assert result["failed_login_count"] == 2
    assert result["repeated_events"][0]["rule"]
    assert result["timeline"][0]["timestamp"] == "2025-01-01T00:00:00Z"


def test_rule_explanation_supports_time_window():
    timestamp = datetime.now(timezone.utc).isoformat()
    matched, explanation = explain_condition(
        {"field": "timestamp", "operator": "within_minutes", "value": 5},
        {"event_timestamp": timestamp},
    )
    assert matched is True
    assert "within_minutes" in explanation


def test_mocked_virustotal_result_is_attributed_and_cached(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    value = "c" * 64
    calls = []

    def fake_request(*args, **kwargs):
        calls.append((args, kwargs))
        return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0}}}}

    monkeypatch.setattr(intelligence, "_http_request", fake_request)
    first = intelligence.investigate("hash", value)
    second = intelligence.investigate("hash", value)
    assert first["externally_queried"] is True
    assert first["results"][0]["source"] == "virustotal"
    assert first["verdict"] == "malicious"
    assert second["cached"] is True
    assert len(calls) == 1


def test_mocked_nvd_response_is_normalized(monkeypatch):
    monkeypatch.setenv("NVD_ENABLED", "1")
    monkeypatch.setattr(
        vulnerabilities,
        "_request",
        lambda params: (
            200,
            {
                "totalResults": 1,
                "timestamp": "2025-01-01T00:00:00.000",
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2025-0001",
                            "published": "2025-01-01T00:00:00.000",
                            "lastModified": "2025-01-02T00:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]},
                            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"}],
                        }
                    }
                ],
            },
        ),
    )
    result = vulnerabilities.search("test", None, 1, 20, "HIGH")
    assert result["results"][0]["id"] == "CVE-2025-0001"
    assert result["results"][0]["cvss_score"] == 8.1
    assert result["results"][0]["references"]
