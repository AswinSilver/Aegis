from __future__ import annotations

from sqlalchemy.orm import Session

from ..db.models import AnalysisRecord, Asset, Case, Event
from .ioc import extract_iocs


def _node(node_id: str, kind: str, label: str, source: str, explanation: str, data: dict) -> dict:
    return {
        "id": node_id,
        "kind": kind,
        "type": kind,
        "label": label,
        "source": source,
        "explanation": explanation,
        "data": data,
    }


def build_graph(db: Session, case_id: int | None = None) -> dict:
    cases = list(db.query(Case).order_by(Case.id).all())
    assets = list(db.query(Asset).order_by(Asset.id).all())
    events = list(db.query(Event).order_by(Event.id).all())
    analyses = list(db.query(AnalysisRecord).order_by(AnalysisRecord.id).all())

    if case_id is not None:
        selected_case = next((case for case in cases if case.id == case_id), None)
        if selected_case is None:
            raise LookupError("case not found")
        asset_ids = {asset.id for asset in selected_case.assets}
        event_ids = {event.id for event in selected_case.events}
        cases = [selected_case]
        assets = [asset for asset in assets if asset.id in asset_ids]
        events = [event for event in events if event.id in event_ids]
        # Keep only analysis records with a concrete field match to selected data.
        tokens = {str(value).casefold() for item in [*assets, *events] for value in (getattr(item, "name", None), getattr(item, "hostname", None), getattr(item, "ip", None), getattr(item, "source", None)) if value}
        analyses = [record for record in analyses if record.input_value and record.input_value.casefold() in tokens]

    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def add_node(node: dict) -> None:
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)
    for case in cases:
        add_node(
            _node(
                f"case:{case.id}",
                "case",
                case.title,
                "database.cases",
                "Persisted investigation case.",
                {"id": case.id, "status": case.status, "priority": case.priority, "assignee": case.assignee},
            )
        )
    for asset in assets:
        add_node(
            _node(
                f"asset:{asset.id}",
                "asset",
                asset.name,
                "database.assets",
                "Persisted asset inventory record.",
                {"id": asset.id, "hostname": asset.hostname, "ip": asset.ip, "kind": asset.kind, "risk": asset.risk, "status": asset.status},
            )
        )
    for event in events:
        add_node(
            _node(
                f"event:{event.id}",
                "event",
                event.event_type or f"event-{event.id}",
                "database.events",
                "Persisted imported event record.",
                {"id": event.id, "source": event.source, "timestamp": event.event_timestamp, "severity": event.severity, "detail": event.detail},
            )
        )
    for record in analyses:
        add_node(
            _node(
                f"analysis:{record.id}",
                "analysis",
                record.analysis_type,
                record.source,
                record.explanation,
                {"id": record.id, "input": record.input_value, "result": record.result_json},
            )
        )

    indicator_tokens: dict[str, tuple[str, str]] = {}

    def add_indicator(kind: str, value: str, source: str, explanation: str) -> str:
        normalized = value.casefold()
        node_id = f"indicator:{kind}:{normalized}"
        indicator_tokens[normalized] = (kind, node_id)
        add_node(_node(node_id, kind, value, source, explanation, {"value": value, "indicator_type": kind}))
        return node_id

    # Indicator nodes are derived only from persisted analysis payloads and
    # persisted case annotations.  No relationships are inferred from random
    # topology or fabricated threat data.
    for case in cases:
        for indicator in case.indicators_json or []:
            if isinstance(indicator, str) and indicator.strip():
                add_indicator("indicator", indicator.strip(), "database.case_indicators", "Analyst-attached indicator on a persisted case.")
        for vulnerability_id in case.vulnerability_ids_json or []:
            if isinstance(vulnerability_id, str) and vulnerability_id.strip():
                add_indicator("vulnerability", vulnerability_id.strip().upper(), "database.case_vulnerabilities", "Analyst-attached vulnerability identifier on a persisted case.")
    for record in analyses:
        result = record.result_json if isinstance(record.result_json, dict) else {}
        indicator = result.get("indicator")
        indicator_type = result.get("indicator_type")
        if isinstance(indicator, str) and isinstance(indicator_type, str):
            add_indicator(indicator_type, indicator, record.source, "Indicator returned by a persisted intelligence analysis.")
        for cve in result.get("cves", []) if isinstance(result.get("cves"), list) else []:
            if isinstance(cve, str):
                add_indicator("vulnerability", cve.upper(), record.source, "CVE extracted by a persisted local analysis.")

    for event in events:
        event_text = " ".join(filter(None, [event.source, event.detail, event.event_type, str(event.payload_json or {})]))
        extracted = extract_iocs(event_text)
        for kind, values in (("url", extracted["urls"]), ("ipv4", extracted["ipv4"]), ("ipv6", extracted["ipv6"]), ("domain", extracted["domains"]), ("vulnerability", extracted["cves"])):
            for value in values:
                add_indicator(kind, value, "database.events.payload", "Indicator extracted from a persisted event field; extraction is not a maliciousness verdict.")
        for kind, values in extracted["hashes"].items():
            for value in values:
                add_indicator("hash", value, "database.events.payload", "File hash extracted from a persisted event field.")

    edge_ids: set[str] = set()

    def add_edge(source: str, target: str, relation: str, source_name: str, explanation: str) -> None:
        edge_id = f"{source}->{target}:{relation}"
        if edge_id in edge_ids:
            return
        edge_ids.add(edge_id)
        edges.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "relation": relation,
                "type": relation,
                "source_attribution": source_name,
                "evidence_source": source_name,
                "explanation": explanation,
            }
        )

    for case in cases:
        for asset in case.assets:
            if any(item.id == asset.id for item in assets):
                add_edge(f"case:{case.id}", f"asset:{asset.id}", "contains_asset", "database.case_assets", "Persisted case-to-asset association.")
        for event in case.events:
            if any(item.id == event.id for item in events):
                add_edge(f"case:{case.id}", f"event:{event.id}", "contains_event", "database.case_events", "Persisted case-to-event association.")
        for indicator in case.indicators_json or []:
            if isinstance(indicator, str) and indicator.casefold() in indicator_tokens:
                add_edge(f"case:{case.id}", indicator_tokens[indicator.casefold()][1], "references_indicator", "database.case_indicators", "Analyst-attached case indicator.")
        for vulnerability_id in case.vulnerability_ids_json or []:
            if isinstance(vulnerability_id, str) and vulnerability_id.casefold() in indicator_tokens:
                add_edge(f"case:{case.id}", indicator_tokens[vulnerability_id.casefold()][1], "references_vulnerability", "database.case_vulnerabilities", "Analyst-attached case vulnerability.")

    asset_by_token: dict[str, Asset] = {}
    for asset in assets:
        for value in (asset.name, asset.hostname, asset.ip):
            if value:
                asset_by_token[value.casefold()] = asset
    for event in events:
        if event.source and event.source.casefold() in asset_by_token:
            asset = asset_by_token[event.source.casefold()]
            add_edge(f"event:{event.id}", f"asset:{asset.id}", "observed_on", "database.events.source", "Deterministic match between the persisted event source and asset identity.")
    for record in analyses:
        if record.input_value:
            asset = asset_by_token.get(record.input_value.casefold())
            if asset:
                add_edge(f"analysis:{record.id}", f"asset:{asset.id}", "analyzes", record.source, "Persisted analysis input matches an asset identity.")
            for event in events:
                haystack = " ".join(filter(None, [event.source, event.detail, event.event_type])).casefold()
                if record.input_value.casefold() in haystack:
                    add_edge(f"analysis:{record.id}", f"event:{event.id}", "references", record.source, "Persisted analysis input appears in a persisted event field.")
        indicator = record.result_json.get("indicator") if isinstance(record.result_json, dict) else None
        indicator_type = record.result_json.get("indicator_type") if isinstance(record.result_json, dict) else None
        if isinstance(indicator, str) and isinstance(indicator_type, str):
            node_id = indicator_tokens.get(indicator.casefold(), (indicator_type, f"indicator:{indicator_type}:{indicator.casefold()}"))[1]
            add_edge(f"analysis:{record.id}", node_id, "produced", record.source, "Persisted analysis produced this indicator record.")

    for event in events:
        event_text = " ".join(filter(None, [event.source, event.detail, event.event_type, str(event.payload_json or {})])).casefold()
        for token, (_kind, node_id) in indicator_tokens.items():
            if token and token in event_text:
                add_edge(f"event:{event.id}", node_id, "contains_indicator", "database.events.payload", "Indicator value appears in a persisted event field.")

    return {"nodes": nodes, "edges": edges, "source": "sqlite.persisted_records"}
