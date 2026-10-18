from __future__ import annotations

from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from typing import Any


ALLOWED_OPERATORS = {"equals", "not_equals", "contains", "starts_with", "gt", "gte", "lt", "lte", "within_minutes"}
MAX_DEPTH = 20
MAX_NODES = 200


def normalize_condition(condition: dict[str, Any], depth: int = 0, counter: list[int] | None = None) -> dict[str, Any]:
    """Validate/normalize a condition tree without evaluating code from it."""

    counter = counter or [0]
    counter[0] += 1
    if depth > MAX_DEPTH or counter[0] > MAX_NODES or not isinstance(condition, dict):
        raise ValueError("condition tree is too deep or large")
    child_values = condition.get("conditions")
    if child_values is None:
        child_values = condition.get("children")
    operator_value = str(condition.get("operator") or "").lower()
    logical = str(condition.get("op") or condition.get("type") or (operator_value if child_values and operator_value in {"and", "or"} else "")).lower()
    if logical:
        if logical not in {"and", "or"} or not isinstance(child_values, list) or not child_values:
            raise ValueError("logical condition requires AND/OR and a non-empty conditions list")
        return {"op": logical, "conditions": [normalize_condition(child, depth + 1, counter) for child in child_values]}

    field = condition.get("field")
    operator = operator_value
    if not isinstance(field, str) or not field or not all(ch.isalnum() or ch in "._-" for ch in field):
        raise ValueError("condition field is invalid")
    if operator not in ALLOWED_OPERATORS:
        raise ValueError("condition operator is not supported")
    return {"field": field, "operator": operator, "value": condition.get("value")}


def _field_value(event: dict[str, Any], field: str) -> Any:
    aliases = {
        "type": "event_type",
        "timestamp": "event_timestamp",
        "time": "event_timestamp",
        "message": "detail",
    }
    current: Any = event
    for part in field.split("."):
        if isinstance(current, dict):
            key = aliases.get(part, part)
            if part == "payload" and isinstance(current.get("payload_json"), dict):
                current = current["payload_json"]
            elif part == "normalized" and isinstance(current.get("normalized_json"), dict):
                current = current["normalized_json"]
            elif key in current:
                current = current[key]
            elif part in current:
                current = current[part]
            elif isinstance(current.get("payload"), dict) and part in current["payload"]:
                current = current["payload"][part]
            elif isinstance(current.get("payload_json"), dict) and part in current["payload_json"]:
                current = current["payload_json"][part]
            else:
                return None
        else:
            return None
    return current


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _number(value: Any) -> Decimal | None:
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None


def _leaf_matches(node: dict[str, Any], event: dict[str, Any]) -> bool:
    actual = _field_value(event, node["field"])
    expected = node.get("value")
    operator = node["operator"]
    if operator == "equals":
        if isinstance(actual, str) or isinstance(expected, str):
            return _string(actual).casefold() == _string(expected).casefold()
        return actual == expected
    if operator == "not_equals":
        if isinstance(actual, str) or isinstance(expected, str):
            return _string(actual).casefold() != _string(expected).casefold()
        return actual != expected
    if operator == "contains":
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        return _string(expected).casefold() in _string(actual).casefold()
    if operator == "starts_with":
        return _string(actual).casefold().startswith(_string(expected).casefold())
    if operator == "within_minutes":
        try:
            parsed = datetime.fromisoformat(_string(actual).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            minutes = float(expected)
        except (ValueError, TypeError):
            return False
        age_seconds = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
        return 0 <= age_seconds <= minutes * 60
    actual_number = _number(actual)
    expected_number = _number(expected)
    if actual_number is None or expected_number is None:
        return False
    if operator == "gt":
        return actual_number > expected_number
    if operator == "gte":
        return actual_number >= expected_number
    if operator == "lt":
        return actual_number < expected_number
    if operator == "lte":
        return actual_number <= expected_number
    return False


def evaluate_condition(condition: dict[str, Any], event: dict[str, Any], depth: int = 0) -> bool:
    if depth > MAX_DEPTH:
        return False
    logical = condition.get("op")
    if logical == "and":
        return all(evaluate_condition(child, event, depth + 1) for child in condition["conditions"])
    if logical == "or":
        return any(evaluate_condition(child, event, depth + 1) for child in condition["conditions"])
    return _leaf_matches(condition, event)


def explain_condition(condition: dict[str, Any], event: dict[str, Any], depth: int = 0) -> tuple[bool, str]:
    """Evaluate the bounded condition tree and return an analyst-readable trace."""

    if depth > MAX_DEPTH:
        return False, "condition depth exceeded the safety limit"
    logical = condition.get("op")
    if logical in {"and", "or"}:
        children = [explain_condition(child, event, depth + 1) for child in condition.get("conditions", [])]
        matched = all(item[0] for item in children) if logical == "and" else any(item[0] for item in children)
        details = f" {logical.upper()} ".join(item[1] for item in children)
        return matched, f"{logical.upper()} group => {'matched' if matched else 'not matched'} ({details})"
    actual = _field_value(event, condition.get("field", ""))
    matched = _leaf_matches(condition, event)
    return matched, f"{condition.get('field')} {condition.get('operator')} {condition.get('value')!r}; actual={actual!r} => {'matched' if matched else 'not matched'}"
