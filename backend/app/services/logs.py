from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any


FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "@timestamp", "datetime", "date"),
    "source": ("source", "source_ip", "src_ip", "host", "hostname", "client_ip", "ip"),
    "username": ("username", "user", "user_name", "account", "principal", "email"),
    "event_type": ("event_type", "type", "action", "event", "category"),
    "status": ("status", "result", "outcome", "authentication_result", "disposition"),
    "severity": ("severity", "level", "priority"),
    "detail": ("detail", "message", "description", "reason", "command"),
}


def _first(record: dict[str, Any], names: tuple[str, ...]) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        if name in lowered and lowered[name] not in (None, ""):
            return lowered[name]
    return None


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        field: _first(record, aliases) for field, aliases in FIELD_ALIASES.items()
    }
    normalized["raw"] = record
    for key, value in list(normalized.items()):
        if key != "raw" and value is not None:
            normalized[key] = str(value).strip()
    normalized["timestamp_normalized"] = normalize_timestamp(normalized.get("timestamp"))
    return normalized


def normalize_timestamp(value: Any) -> str | None:
    """Normalize common ISO/RFC timestamps without guessing missing timezones."""

    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def is_failed_login(record: dict[str, Any]) -> bool:
    normalized = normalize_record(record)
    status = (normalized.get("status") or "").lower()
    event_type = (normalized.get("event_type") or "").lower()
    detail = (normalized.get("detail") or "").lower()
    login_context = any(word in f"{event_type} {detail}" for word in ("login", "logon", "auth", "sign-in", "signin"))
    failed_status = any(word in status for word in ("fail", "invalid", "denied", "deny", "unauthor", "error", "reject"))
    return login_context and failed_status or status in {"failure", "failed", "denied", "invalid"}


def parse_log_input(value: Any, content_type: str | None = None) -> tuple[str, list[dict[str, Any]]]:
    """Parse JSON arrays/objects, JSONL, or CSV without evaluating user content."""

    if isinstance(value, list):
        records = [item for item in value if isinstance(item, dict)]
        if len(records) != len(value):
            raise ValueError("JSON log input must contain only objects")
        return "json", records
    if isinstance(value, dict):
        for key in ("events", "logs", "records", "items", "data", "assets", "content"):
            if isinstance(value.get(key), list):
                records = value[key]
                if not all(isinstance(item, dict) for item in records):
                    raise ValueError("JSON log input must contain only objects")
                return "json", records
        for key in ("text", "content", "input", "csv", "json"):
            if isinstance(value.get(key), str):
                return parse_log_input(value[key], content_type)
        return "json", [value]
    if not isinstance(value, str):
        raise ValueError("log input must be JSON, JSONL, or CSV text")
    text = value.lstrip("\ufeff")
    if not text.strip():
        return "text", []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        return parse_log_input(parsed, "application/json")
    lines = [line for line in text.splitlines() if line.strip()]
    if lines and all(line.lstrip().startswith(("{", "[")) for line in lines):
        records = []
        for line in lines:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("JSONL log input must contain objects")
            records.append(item)
        return "jsonl", records
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV log input must include a header row")
    return "csv", [dict(row) for row in reader]


def analyze_logs(value: Any, content_type: str | None = None) -> dict:
    format_name, records = parse_log_input(value, content_type)
    normalized = [normalize_record(record) for record in records]
    failed = [record for record in normalized if is_failed_login(record)]

    by_source: Counter[str] = Counter((record.get("source") or "unknown") for record in failed)
    by_username: Counter[str] = Counter((record.get("username") or "unknown") for record in failed)
    grouped: Counter[str] = Counter(
        f"{record.get('event_type') or 'unknown'}|{record.get('source') or 'unknown'}" for record in normalized
    )
    repeated_events = [
        {"group": key, "count": count, "rule": "same event_type and source appeared at least twice"}
        for key, count in grouped.items()
        if count >= 2
    ]
    # This is an explicit, deterministic heuristic rather than a claim of
    # maliciousness: a group is unusual only when it is at least triple the
    # mean group size and contains five or more records.
    average_group_size = (sum(grouped.values()) / len(grouped)) if grouped else 0
    unusual_frequency = [
        {
            "group": key,
            "count": count,
            "rule": "count >= 5 and count >= 3x the mean event-group size",
        }
        for key, count in grouped.items()
        if count >= 5 and average_group_size and count >= average_group_size * 3
    ]
    timeline = [
        {
            "timestamp": record.get("timestamp_normalized") or record.get("timestamp"),
            "event_type": record.get("event_type"),
            "source": record.get("source"),
            "severity": record.get("severity"),
            "detail": record.get("detail"),
        }
        for record in normalized
    ]
    observations: list[dict[str, str]] = [
        {
            "source": "local.log_parser",
            "explanation": "Records were parsed and normalized locally; failed-login counts use status and authentication/login context fields.",
        }
    ]
    if failed:
        observations.append(
            {
                "source": "local.log_parser",
                "explanation": f"Detected {len(failed)} failed authentication record(s) from the supplied input.",
            }
        )
    if repeated_events:
        observations.append(
            {
                "source": "local.log_parser",
                "explanation": f"Repeated-event observation: {len(repeated_events)} event/source group(s) occurred at least twice; repetition alone is not a maliciousness verdict.",
            }
        )
    if unusual_frequency:
        observations.append(
            {
                "source": "local.log_parser",
                "explanation": f"Frequency observation: {len(unusual_frequency)} group(s) met the explicit >=5 and >=3x mean threshold.",
            }
        )
    return {
        "format": format_name,
        "total_records": len(records),
        "normalized_records": normalized,
        "failed_login_count": len(failed),
        "groups": {
            "failed_logins_by_source": dict(by_source),
            "failed_logins_by_username": dict(by_username),
            "event_type_source": dict(grouped),
        },
        "repeated_events": repeated_events,
        "unusual_frequency": unusual_frequency,
        "timeline": timeline,
        "observations": observations,
    }
