from __future__ import annotations

import csv
import io
import json
from typing import Any

from sqlalchemy.orm import Session

from ..db.models import AnalysisRecord, Case


def _analysis_for_case(case: Case, records: list[AnalysisRecord]) -> list[AnalysisRecord]:
    tokens = {
        str(value).casefold()
        for item in [*case.assets, *case.events]
        for value in (
            getattr(item, "name", None),
            getattr(item, "hostname", None),
            getattr(item, "ip", None),
            getattr(item, "source", None),
        )
        if value
    }
    return [record for record in records if record.input_value and record.input_value.casefold() in tokens]


def build_case_report(db: Session, case_id: int) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise LookupError("case not found")
    analyses = _analysis_for_case(case, list(db.query(AnalysisRecord).order_by(AnalysisRecord.id).all()))
    return {
        "case": {
            "id": case.id,
            "title": case.title,
            "description": case.description,
            "status": case.status,
            "priority": case.priority,
            "assignee": case.assignee,
            "metadata": case.metadata_json,
            "related_indicators": case.indicators_json or [],
            "vulnerability_ids": case.vulnerability_ids_json or [],
            "analyst_notes": case.analyst_notes,
            "activities": [
                {"id": activity.id, "action": activity.action, "detail": activity.detail, "actor": activity.actor, "created_at": activity.created_at.isoformat() if activity.created_at else None}
                for activity in case.activities
            ],
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        },
        "assets": [
            {
                "id": asset.id,
                "name": asset.name,
                "hostname": asset.hostname,
                "ip": asset.ip,
                "kind": asset.kind,
                "risk": asset.risk,
                "status": asset.status,
            }
            for asset in case.assets
        ],
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "source": event.source,
                "timestamp": event.event_timestamp,
                "severity": event.severity,
                "detail": event.detail,
                "payload": event.payload_json,
            }
            for event in case.events
        ],
        "analysis_records": [
            {
                "id": record.id,
                "analysis_type": record.analysis_type,
                "input": record.input_value,
                "source": record.source,
                "explanation": record.explanation,
                "result": record.result_json,
                "created_at": record.created_at.isoformat() if record.created_at else None,
            }
            for record in analyses
        ],
        "source": "sqlite.persisted_records",
        "explanation": "This report contains only records persisted in the selected case and deterministic analysis matches.",
    }


def case_report_csv(report: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["section", "id", "type", "name", "source", "severity", "detail", "explanation", "data_json"])
    case = report["case"]
    writer.writerow(["case", case["id"], "case", case["title"], "database.cases", case["priority"], case["description"] or "", report["explanation"], json.dumps(case, sort_keys=True)])
    for asset in report["assets"]:
        writer.writerow(["asset", asset["id"], "asset", asset["name"], "database.assets", asset.get("risk") or "", "", "Persisted case asset", json.dumps(asset, sort_keys=True)])
    for event in report["events"]:
        writer.writerow(["event", event["id"], event.get("event_type") or "event", event.get("source") or "", "database.events", event.get("severity") or "", event.get("detail") or "", "Persisted case event", json.dumps(event, sort_keys=True)])
    for analysis in report["analysis_records"]:
        writer.writerow(["analysis", analysis["id"], analysis["analysis_type"], analysis.get("input") or "", analysis["source"], "", "", analysis["explanation"], json.dumps(analysis, sort_keys=True)])
    return output.getvalue()


def case_report_pdf(report: dict[str, Any]) -> bytes:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError as exc:  # pragma: no cover - depends on optional installation
        raise RuntimeError("reportlab is not installed") from exc

    output = io.BytesIO()
    document = SimpleDocTemplate(output, pagesize=letter, rightMargin=0.5 * inch, leftMargin=0.5 * inch, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    case = report["case"]
    story = [Paragraph("BLACKSITE Case Report", styles["Title"]), Paragraph(case["title"], styles["Heading2"]), Paragraph(f"Status: {case['status']} · Priority: {case['priority']}", styles["BodyText"]), Spacer(1, 12)]
    rows = [["Section", "Identifier", "Source", "Summary"]]
    rows.append(["Case", str(case["id"]), "database.cases", case["title"]])
    rows.extend([["Asset", str(item["id"]), "database.assets", item["name"]] for item in report["assets"]])
    rows.extend([["Event", str(item["id"]), "database.events", (item.get("detail") or item.get("event_type") or "")[:180]] for item in report["events"]])
    rows.extend([["Analysis", str(item["id"]), item["source"], (item["explanation"] or "")[:180]] for item in report["analysis_records"]])
    table = Table(rows, colWidths=[0.8 * inch, 0.8 * inch, 1.5 * inch, 4.2 * inch], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222222")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph(report["explanation"], styles["BodyText"]))
    document.build(story)
    return output.getvalue()
