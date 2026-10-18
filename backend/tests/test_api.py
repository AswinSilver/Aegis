from __future__ import annotations

import io
import json


def test_health_and_local_hash(client):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["database"] == "ok"
    assert client.get("/api/graph").json()["nodes"] == []

    response = client.post(
        "/api/forensics/hash",
        files={"file": ("sample.txt", io.BytesIO(b"hello blacksite"), "text/plain")},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["hashes"]["sha256"] == "1b740e1165992e3792872675182c2137f46cbedbbe4ad0ccc7df37644e24b942"
    assert payload["executed"] is False
    assert payload["uploaded_externally"] is False


def test_extract_logs_and_events(client):
    extract = client.post(
        "/api/forensics/extract",
        json={"text": "Connect to https://example.com/a from 192.0.2.10; sha256 " + "a" * 64},
    )
    assert extract.status_code == 200
    assert "https://example.com/a" in extract.json()["urls"]
    assert "192.0.2.10" in extract.json()["ipv4"]

    uploaded_extract = client.post(
        "/api/forensics/extract",
        files={"file": ("evidence.txt", b"https://example.org/path 198.51.100.7", "text/plain")},
    )
    assert uploaded_extract.status_code == 200
    assert uploaded_extract.json()["input_metadata"]["filename"] == "evidence.txt"

    logs = client.post(
        "/api/forensics/logs",
        content="timestamp,source,username,event_type,status\n2025-01-01T00:00:00Z,10.0.0.1,alice,login,failed\n",
        headers={"content-type": "text/csv"},
    )
    assert logs.status_code == 200
    assert logs.json()["failed_login_count"] == 1

    imported = client.post(
        "/api/events/import",
        json={"events": [{"event_type": "login", "source": "gateway-1", "status": "failed", "severity": "high"}]},
    )
    assert imported.status_code == 201
    assert imported.json()["imported"] == 1
    assert client.get("/api/events").json()["total"] == 1

    assets = client.post("/api/assets/import", content="name,ip\nserver-1,10.0.0.8\n", headers={"content-type": "text/csv"})
    assert assets.status_code == 201
    assert assets.json()["imported"] == 1


def test_rules_evaluate_persisted_events_and_crud(client):
    imported = client.post(
        "/api/events/import",
        json={"events": [{"event_type": "login", "source": "gateway-1", "status": "failed", "attempts": 5}, {"event_type": "dns", "source": "dns-1", "status": "ok"}]},
    )
    assert imported.status_code == 201
    rule = client.post(
        "/api/rules",
        json={
            "name": "failed gateway login",
            "condition": {"op": "and", "conditions": [{"field": "event_type", "operator": "equals", "value": "login"}, {"field": "status", "operator": "equals", "value": "failed"}]},
        },
    )
    assert rule.status_code == 201, rule.text
    tested = client.post(f"/api/rules/{rule.json()['id']}/test")
    assert tested.status_code == 200
    assert tested.json()["matched_count"] == 1
    assert client.patch(f"/api/rules/{rule.json()['id']}", json={"enabled": False}).status_code == 200
    assert client.delete(f"/api/rules/{rule.json()['id']}").json()["deleted"] is True


def test_cases_assets_graph_and_reports(client):
    asset = client.post("/api/assets", json={"name": "gateway-1", "ip": "10.0.0.5", "kind": "gateway"})
    assert asset.status_code == 201
    event = client.post("/api/events/import", json={"events": [{"event_type": "network", "source": "gateway-1", "detail": "observed"}]})
    event_id = event.json()["items"][0]["id"]
    case = client.post("/api/cases", json={"title": "Gateway review", "asset_ids": [asset.json()["id"]], "event_ids": [event_id]})
    assert case.status_code == 201
    case_id = case.json()["id"]

    graph = client.get("/api/graph")
    assert graph.status_code == 200
    assert {node["kind"] for node in graph.json()["nodes"]} >= {"case", "asset", "event"}
    assert any(edge["relation"] == "contains_asset" for edge in graph.json()["edges"])
    assert client.get("/api/graph.json").headers["content-disposition"].endswith("blacksite-graph.json")

    report = client.get(f"/api/reports/cases/{case_id}.json")
    assert report.status_code == 200
    assert report.json()["case"]["title"] == "Gateway review"
    assert client.get(f"/api/reports/cases/{case_id}.csv").status_code == 200
    assert client.get(f"/api/reports/cases/{case_id}.pdf").status_code in {200, 501}


def test_intelligence_is_honest_and_blocks_private_destinations(client):
    public = client.post("/api/intelligence/ip", json={"indicator": "192.0.2.10"})
    assert public.status_code == 200
    assert public.json()["verdict"] in {"no_result", "unavailable"}
    assert public.json()["externally_queried"] is False
    private = client.post("/api/intelligence/ip", json={"indicator": "10.0.0.1"})
    assert private.status_code == 200
    assert private.json()["classification"] == "private"
    assert private.json()["externally_queried"] is False
    assert client.post("/api/intelligence/hash", json={"indicator": "not-a-hash"}).status_code == 422


def test_nvd_without_configuration_is_explicitly_unavailable(client):
    response = client.get("/api/vulnerabilities/search", params={"q": "CVE-2024-1234"})
    assert response.status_code == 503
    assert "not configured" in response.json()["detail"]


def test_log_observations_timestamp_and_file_type(client):
    logs = client.post(
        "/api/forensics/logs",
        json={
            "format": "json",
            "content": [
                {"timestamp": "2025-01-01T00:00:00+02:00", "source": "gw", "event_type": "login", "status": "failed"},
                {"timestamp": "2024-12-31T22:00:00Z", "source": "gw", "event_type": "login", "status": "failed"},
            ],
        },
    )
    assert logs.status_code == 200
    payload = logs.json()
    assert payload["normalized_records"][0]["timestamp_normalized"] == "2024-12-31T22:00:00Z"
    assert payload["failed_login_count"] == 2
    assert payload["repeated_events"][0]["count"] == 2

    hashed = client.post("/api/forensics/hash", files={"file": ("image.png", io.BytesIO(b"\x89PNG\r\n\x1a\nrest"), "image/png")})
    assert hashed.status_code == 200
    assert hashed.json()["metadata"]["detected_file_type"] == "PNG image"


def test_case_notes_indicators_and_asset_assessment_guard(client):
    asset = client.post("/api/assets", json={"name": "local-gateway", "ip": "127.0.0.1", "owner": "blue-team", "operating_system": "Linux"})
    assert asset.status_code == 201
    asset_id = asset.json()["id"]
    assert asset.json()["owner"] == "blue-team"
    denied = client.post(f"/api/assets/{asset_id}/assess", json={"kind": "tcp", "port": 1, "confirm_authorized": False})
    assert denied.status_code == 422
    case = client.post(
        "/api/cases",
        json={"title": "Indicator review", "asset_ids": [asset_id], "indicators": ["192.0.2.10"], "vulnerability_ids": ["CVE-2024-1234"]},
    )
    assert case.status_code == 201
    case_id = case.json()["id"]
    note = client.post(f"/api/cases/{case_id}/notes", json={"detail": "Analyst note: indicator requires external confirmation."})
    assert note.status_code == 201
    refreshed = client.get(f"/api/cases/{case_id}").json()
    assert refreshed["analyst_notes"]
    assert refreshed["activities"]
    graph = client.get("/api/graph").json()
    assert any(node["kind"] == "vulnerability" for node in graph["nodes"])
    assert any(edge["relation"] == "references_vulnerability" for edge in graph["edges"])
