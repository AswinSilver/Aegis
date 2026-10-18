from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
import time
from contextlib import asynccontextmanager
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import PurePath
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from .db.models import AnalysisRecord, Asset, AuditLog, Case, CaseActivity, Event, Rule
from .db.setup import SessionLocal, get_db, init_db
from .schemas import (
    AssetCreate,
    AssetAssessmentRequest,
    AssetUpdate,
    CaseCreate,
    CaseNoteCreate,
    CaseUpdate,
    ConditionNode,
    IndicatorRequest,
    RuleCreate,
    RuleTestRequest,
    RuleUpdate,
)
from .services.graph import build_graph
from .services.hashing import EvidenceTooLargeError, hash_stream
from .services.intelligence import investigate
from .services.ioc import extract_iocs
from .services.logs import analyze_logs, normalize_record, parse_log_input
from .services.reports import build_case_report, case_report_csv, case_report_pdf
from .services.rules import evaluate_condition, explain_condition, normalize_condition
from .services.vulnerabilities import CVE_RE, nvd_configured, search as search_vulnerabilities


APP_VERSION = "1.0.0"
MAX_REQUEST_BYTES = int(os.getenv("MAX_REQUEST_BYTES", str(25 * 1024 * 1024)))
MAX_TEXT_BYTES = int(os.getenv("MAX_TEXT_BYTES", str(20 * 1024 * 1024)))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "240"))



@asynccontextmanager
async def lifespan(_application: FastAPI):
    init_db()
    yield


app = FastAPI(title="Aegis Backend", version=APP_VERSION, lifespan=lifespan)
# Create the local schema during import as well as startup so lightweight ASGI
# clients that do not enter a lifespan context still receive a usable API.
init_db()

origins = [item.strip() for item in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

_rate_buckets: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def request_limits(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(status_code=413, content={"error": "request_too_large", "detail": "request exceeds the configured size limit"})
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "invalid_content_length"})

    client_host = request.client.host if request.client else "unknown"
    bucket_key = f"{client_host}:{request.url.path}"
    now = time.monotonic()
    bucket = _rate_buckets[bucket_key]
    while bucket and now - bucket[0] >= 60:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MINUTE and request.url.path != "/api/health":
        return JSONResponse(status_code=429, content={"error": "rate_limited", "detail": "too many requests"}, headers={"Retry-After": "60"})
    bucket.append(now)
    try:
        response = await asyncio.wait_for(call_next(request), timeout=REQUEST_TIMEOUT_SECONDS)
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.url.path.startswith("/api/"):
            try:
                with SessionLocal() as db:
                    db.add(AuditLog(method=request.method, path=request.url.path, status_code=response.status_code, actor=client_host))
                    db.commit()
            except Exception:
                # Audit logging must never turn an otherwise successful action
                # into a 500, but the failure remains visible in server logs.
                pass
        return response
    except asyncio.TimeoutError:
        return JSONResponse(status_code=504, content={"error": "request_timeout", "detail": "request exceeded the configured timeout"})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    errors = [{"loc": list(error.get("loc", ())), "msg": error.get("msg", "invalid request"), "type": error.get("type", "validation_error")} for error in exc.errors()]
    return JSONResponse(status_code=422, content={"error": "validation_error", "details": errors})


@app.exception_handler(HTTPException)
async def http_error_handler(_request: Request, exc: HTTPException):
    detail = exc.detail if isinstance(exc.detail, (str, dict, list)) else "request failed"
    return JSONResponse(status_code=exc.status_code, content={"error": "request_error", "detail": detail}, headers=exc.headers)


@app.exception_handler(Exception)
async def unhandled_error_handler(_request: Request, _exc: Exception):
    # Do not return tracebacks, database paths, API keys, or upstream bodies.
    return JSONResponse(status_code=500, content={"error": "internal_error", "detail": "the server could not complete the request"})


def _safe_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    return value


async def _request_value(request: Request, max_bytes: int = MAX_TEXT_BYTES) -> tuple[Any, str | None, str | None]:
    """Return (parsed value/text, filename, content type) for JSON, text, or multipart."""

    content_type = request.headers.get("content-type", "").lower()
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        upload: UploadFile | None = None
        for key in ("file", "upload", "evidence"):
            candidate = form.get(key)
            # Starlette may return its UploadFile class while FastAPI exposes a
            # compatible subclass, so use the common file protocol here.
            if isinstance(candidate, UploadFile) or (candidate is not None and hasattr(candidate, "read") and hasattr(candidate, "filename")):
                upload = candidate
                break
        if upload is not None:
            data = await upload.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise HTTPException(status_code=413, detail="uploaded content exceeds the configured size limit")
            try:
                value: Any = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise HTTPException(status_code=415, detail="uploaded text must be UTF-8") from exc
            return value, PurePath(upload.filename or "evidence").name, upload.content_type
        for key in ("text", "content", "data", "input", "json", "payload"):
            if key in form:
                return form.get(key), None, content_type
        raise HTTPException(status_code=400, detail="multipart request needs a file or text field")

    body = await request.body()
    if len(body) > max_bytes:
        raise HTTPException(status_code=413, detail="request content exceeds the configured size limit")
    if not body:
        return "", None, content_type
    if "application/json" in content_type or "json" in content_type:
        try:
            return json.loads(body), None, content_type
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="request body is not valid JSON") from exc
    try:
        return body.decode("utf-8"), None, content_type
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=415, detail="text request body must be UTF-8") from exc


def _text_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "evidence", "data", "input"):
            if isinstance(value.get(key), str):
                return value[key]
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False)


def _condition_dict(node: ConditionNode | None) -> dict[str, Any]:
    if node is None:
        raise HTTPException(status_code=422, detail="condition is required")
    raw = node.model_dump(by_alias=True, exclude_none=True)
    return normalize_condition(raw)


def _case_dict(case: Case) -> dict[str, Any]:
    return {
        "id": case.id,
        "title": case.title,
        "name": case.title,
        "description": case.description,
        "status": case.status,
        "priority": case.priority,
        "assignee": case.assignee,
        "metadata": case.metadata_json,
        "related_indicators": case.indicators_json or [],
        "indicators": case.indicators_json or [],
        "vulnerability_ids": case.vulnerability_ids_json or [],
        "analyst_notes": case.analyst_notes,
        "asset_ids": [asset.id for asset in case.assets],
        "event_ids": [event.id for event in case.events],
        "activities": [
            {
                "id": activity.id,
                "action": activity.action,
                "detail": activity.detail,
                "actor": activity.actor,
                "created_at": activity.created_at.isoformat() if activity.created_at else None,
            }
            for activity in case.activities
        ],
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }


def _asset_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "name": asset.name,
        "hostname": asset.hostname,
        "ip": asset.ip,
        "kind": asset.kind,
        "risk": asset.risk,
        "status": asset.status,
        "operating_system": asset.operating_system,
        "owner": asset.owner,
        "software": asset.software_json,
        "last_assessment_date": asset.last_assessment_date,
        "notes": asset.notes,
        "metadata": asset.metadata_json,
        "case_ids": [case.id for case in asset.cases],
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


def _event_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "type": event.event_type,
        "source": event.source,
        "timestamp": event.event_timestamp,
        "severity": event.severity,
        "detail": event.detail,
        "payload": event.payload_json,
        "normalized": event.normalized_json,
        "case_ids": [case.id for case in event.cases],
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


def _rule_dict(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "condition": rule.condition_json,
        "condition_tree": rule.condition_json,
        "tags": rule.tags_json,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _attach_case_relations(db: Session, case: Case, asset_ids: list[int] | None, event_ids: list[int] | None) -> None:
    if asset_ids is not None:
        assets = db.query(Asset).filter(Asset.id.in_(set(asset_ids))).all() if asset_ids else []
        if len(assets) != len(set(asset_ids)):
            raise HTTPException(status_code=404, detail="one or more assets were not found")
        case.assets = assets
    if event_ids is not None:
        events = db.query(Event).filter(Event.id.in_(set(event_ids))).all() if event_ids else []
        if len(events) != len(set(event_ids)):
            raise HTTPException(status_code=404, detail="one or more events were not found")
        case.events = events


def _add_case_activity(db: Session, case: Case, action: str, detail: str, actor: str | None = None) -> None:
    case.activities.append(CaseActivity(action=action, detail=detail, actor=actor or "local-operator"))


def _assessment_target(asset: Asset) -> str:
    target = (asset.hostname or asset.ip or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="asset has no hostname or IP target")
    if len(target) > 255 or any(character in target for character in "/\\?#@"):
        raise HTTPException(status_code=422, detail="asset target is not a valid host or IP address")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not all(character.isalnum() or character in ".-" for character in target) or target.startswith(".") or target.endswith("."):
            raise HTTPException(status_code=422, detail="asset target is not a valid host or IP address")
    return target


def _http_metadata(target: str, port: int | None, timeout: float) -> dict[str, Any]:
    selected_port = port or (443 if port == 443 else 80)
    scheme = "https" if selected_port in {443, 8443} else "http"
    url = f"{scheme}://{target}:{selected_port}/"

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
            return None

    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Aegis-authorized-assessment/1.0"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            return {
                "status": "reachable",
                "http_status": response.status,
                "headers": {key.lower(): value for key, value in response.headers.items() if key.lower() in {"server", "content-type", "content-length", "date"}},
                "redirected": False,
                "target": url,
            }
    except urllib.error.HTTPError as exc:
        return {
            "status": "reachable",
            "http_status": exc.code,
            "headers": {key.lower(): value for key, value in exc.headers.items() if key.lower() in {"server", "content-type", "content-length", "date"}},
            "redirected": 300 <= exc.code < 400,
            "target": url,
        }
    except urllib.error.URLError as exc:
        reason = str(getattr(exc, "reason", exc))
        return {"status": "unavailable", "error": reason[:240], "target": url}
    except TimeoutError:
        return {"status": "timeout", "target": url}


def _tcp_metadata(target: str, port: int, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return {"status": "reachable", "target": target, "port": port, "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}
    except socket.timeout:
        return {"status": "timeout", "target": target, "port": port, "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}
    except OSError as exc:
        return {"status": "unreachable_or_refused", "target": target, "port": port, "error": str(exc)[:240], "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}


def _event_from_record(record: dict[str, Any]) -> Event:
    normalized = normalize_record(record)
    return Event(
        event_type=normalized.get("event_type"),
        source=normalized.get("source"),
        event_timestamp=normalized.get("timestamp"),
        severity=normalized.get("severity"),
        detail=normalized.get("detail"),
        payload_json=_safe_json(record),
        normalized_json=_safe_json(normalized),
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    db_status = "ok"
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"
    return {
        "status": "ok" if db_status == "ok" else "degraded",
        "service": "aegis-backend",
        "version": APP_VERSION,
        "database": db_status,
        "providers": {"abuseipdb": bool(os.getenv("ABUSEIPDB_API_KEY", "").strip()), "virustotal": bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip()), "urlhaus": bool(os.getenv("URLHAUS_API_URL", "").strip()) or os.getenv("URLHAUS_ENABLED", "").lower() in {"1", "true", "yes"}, "nvd": nvd_configured()},
    }


@app.post("/api/forensics/hash")
async def forensic_hash(file: UploadFile = File(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        result = hash_stream(file.file, file.filename, file.content_type)
    except EvidenceTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    record = AnalysisRecord(
        analysis_type="forensics.hash",
        input_value=result["hashes"]["sha256"],
        source="forensics.local_hash",
        explanation="Cryptographic hashes and basic metadata were calculated from the local multipart stream; the file was not executed or forwarded to an external service.",
        result_json=result,
    )
    db.add(record)
    db.commit()
    result["analysis_id"] = record.id
    return result


@app.post("/api/forensics/extract")
async def forensic_extract(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    value, filename, _content_type = await _request_value(request)
    text_value = _text_value(value)
    result = extract_iocs(text_value)
    record = AnalysisRecord(
        analysis_type="forensics.extract",
        input_value=filename or "text_input",
        source="forensics.local_ioc_extraction",
        explanation=result["observations"][0]["explanation"],
        result_json=result,
    )
    db.add(record)
    db.commit()
    result["analysis_id"] = record.id
    result["input_metadata"] = {"filename": filename, "size_bytes": len(text_value.encode("utf-8"))}
    return result


@app.post("/api/forensics/logs")
async def forensic_logs(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    value, filename, content_type = await _request_value(request)
    if isinstance(value, dict) and isinstance(value.get("text"), str):
        value = value["text"]
    elif isinstance(value, dict) and isinstance(value.get("content"), str):
        value = value["content"]
    elif isinstance(value, dict) and isinstance(value.get("input"), str):
        value = value["input"]
    if filename and isinstance(value, str) and filename.lower().endswith(".csv") and not content_type:
        content_type = "text/csv"
    try:
        result = analyze_logs(value, content_type)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record = AnalysisRecord(
        analysis_type="forensics.logs",
        input_value=filename or "log_input",
        source="forensics.local_log_parser",
        explanation=result["observations"][0]["explanation"],
        result_json=result,
    )
    db.add(record)
    db.commit()
    result["analysis_id"] = record.id
    return result


def _intelligence(kind: str, body: IndicatorRequest, db: Session) -> dict[str, Any]:
    try:
        result = investigate(kind, body.selected())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record = AnalysisRecord(
        analysis_type=f"intelligence.{kind}",
        input_value=result["indicator"],
        source="intelligence.local_and_configured_providers",
        explanation=result["explanation"],
        result_json=result,
    )
    db.add(record)
    db.commit()
    result["analysis_id"] = record.id
    return result


@app.post("/api/intelligence/ip")
def intelligence_ip(body: IndicatorRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _intelligence("ip", body, db)


@app.post("/api/intelligence/url")
def intelligence_url(body: IndicatorRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _intelligence("url", body, db)


@app.post("/api/intelligence/domain")
def intelligence_domain(body: IndicatorRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _intelligence("domain", body, db)


@app.post("/api/intelligence/hash")
def intelligence_hash(body: IndicatorRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    return _intelligence("hash", body, db)


@app.get("/api/vulnerabilities/search")
def vulnerability_search(q: str | None = None, keyword: str | None = None, query: str | None = None, cve_id: str | None = None, severity: str | None = None, published_after: str | None = None, published_before: str | None = None, page: int = 1, limit: int = 20) -> dict[str, Any]:
    if page < 1 or limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="page must be positive and limit must be between 1 and 100")
    requested = cve_id or q or query
    if cve_id and not CVE_RE.fullmatch(cve_id.strip()):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2024-1234")
    cve = (cve_id.strip().upper() if cve_id else (requested.strip().upper() if requested and CVE_RE.fullmatch(requested.strip()) else None))
    search_term = keyword or (None if cve else requested)
    if severity and severity.upper() not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        raise HTTPException(status_code=422, detail="severity must be Critical, High, Medium, or Low")
    try:
        return search_vulnerabilities(search_term, cve, page, limit, severity, published_after, published_before)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/vulnerabilities/{cve_id}")
def vulnerability_detail(cve_id: str) -> dict[str, Any]:
    normalized_cve_id = cve_id.strip().upper()
    if not CVE_RE.fullmatch(normalized_cve_id):
        raise HTTPException(status_code=422, detail="cve_id must look like CVE-2024-1234")
    try:
        result = search_vulnerabilities(None, normalized_cve_id, 1, 1)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    if not result["results"]:
        raise HTTPException(status_code=404, detail="NVD returned no result for this CVE")
    return result["results"][0]


@app.post("/api/rules", status_code=201)
def create_rule(body: RuleCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    condition = _condition_dict(body.condition or body.condition_tree)
    rule = Rule(name=body.name, description=body.description, enabled=body.enabled, condition_json=condition, tags_json=body.tags)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return _rule_dict(rule)


@app.get("/api/rules")
def list_rules(db: Session = Depends(get_db)) -> dict[str, Any]:
    rules = db.query(Rule).order_by(Rule.id).all()
    return {"items": [_rule_dict(rule) for rule in rules], "total": len(rules)}


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    return _rule_dict(rule)


def _update_rule(rule: Rule, body: RuleUpdate) -> None:
    data = body.model_dump(exclude_unset=True)
    if "name" in data:
        rule.name = data["name"]
    if "description" in data:
        rule.description = data["description"]
    if "enabled" in data:
        rule.enabled = data["enabled"]
    if "tags" in data:
        rule.tags_json = data["tags"]
    if body.condition is not None or body.condition_tree is not None:
        rule.condition_json = _condition_dict(body.condition or body.condition_tree)


@app.put("/api/rules/{rule_id}")
@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: int, body: RuleUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    _update_rule(rule, body)
    db.commit()
    db.refresh(rule)
    return _rule_dict(rule)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    db.delete(rule)
    db.commit()
    return {"deleted": True, "id": rule_id}


@app.post("/api/rules/{rule_id}/test")
def test_rule(rule_id: int, body: RuleTestRequest | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    requested_ids = body.event_ids if body else None
    query = db.query(Event).order_by(Event.id)
    if requested_ids is not None:
        query = query.filter(Event.id.in_(set(requested_ids))) if requested_ids else query.filter(Event.id == -1)
    events = query.limit(5000).all()
    matches = []
    for event in events:
        event_data = {
            **(event.payload_json or {}),
            "id": event.id,
            "event_type": event.event_type,
            "source": event.source,
            "event_timestamp": event.event_timestamp,
            "severity": event.severity,
            "detail": event.detail,
            "payload_json": event.payload_json,
        }
        if rule.enabled:
            matched, explanation = explain_condition(rule.condition_json, event_data)
        else:
            matched, explanation = False, "rule is disabled; event was not eligible for a match"
        matches.append({"event_id": event.id, "matched": matched, "event_type": event.event_type, "source": event.source, "explanation": explanation})
    return {"rule_id": rule.id, "enabled": rule.enabled, "evaluated_count": len(events), "matched_count": sum(1 for item in matches if item["matched"]), "matches": matches}


@app.post("/api/cases", status_code=201)
def create_case(body: CaseCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = Case(
        title=body.title or body.name or "",
        description=body.description,
        status=body.status,
        priority=body.priority,
        assignee=body.assignee,
        metadata_json=body.metadata,
        indicators_json=body.indicators,
        vulnerability_ids_json=body.vulnerability_ids,
        analyst_notes=body.analyst_notes,
    )
    db.add(case)
    db.flush()
    _attach_case_relations(db, case, body.asset_ids, body.event_ids)
    _add_case_activity(db, case, "created", "Case created with persisted relationships.")
    db.commit()
    db.refresh(case)
    return _case_dict(case)


@app.get("/api/cases")
def list_cases(offset: int = 0, limit: int = 100, status: str | None = None, priority: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    if offset < 0 or limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="offset must be non-negative and limit must be between 1 and 500")
    query = db.query(Case)
    if status:
        query = query.filter(Case.status == status)
    if priority:
        query = query.filter(Case.priority == priority)
    total = query.count()
    cases = query.order_by(Case.id).offset(offset).limit(limit).all()
    return {"items": [_case_dict(case) for case in cases], "total": total, "offset": offset, "limit": limit}


@app.get("/api/cases/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return _case_dict(case)


@app.put("/api/cases/{case_id}")
@app.patch("/api/cases/{case_id}")
def update_case(case_id: int, body: CaseUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    data = body.model_dump(exclude_unset=True)
    title = data.get("title") or data.get("name")
    if title is not None:
        case.title = title
    for field in ("description", "status", "priority", "assignee", "analyst_notes"):
        if field in data:
            setattr(case, field, data[field])
    if "metadata" in data:
        case.metadata_json = data["metadata"] or {}
    if "indicators" in data:
        case.indicators_json = data["indicators"] or []
    if "vulnerability_ids" in data:
        case.vulnerability_ids_json = data["vulnerability_ids"] or []
    _attach_case_relations(db, case, body.asset_ids, body.event_ids)
    _add_case_activity(db, case, "updated", "Case fields or relationships updated.")
    db.commit()
    db.refresh(case)
    return _case_dict(case)


@app.delete("/api/cases/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    db.delete(case)
    db.commit()
    return {"deleted": True, "id": case_id}


@app.post("/api/cases/{case_id}/notes", status_code=201)
def add_case_note(case_id: int, body: CaseNoteCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    activity = CaseActivity(action="note", detail=body.detail.strip(), actor=body.actor or "local-operator")
    case.activities.append(activity)
    case.analyst_notes = ((case.analyst_notes + "\n") if case.analyst_notes else "") + body.detail.strip()
    db.commit()
    db.refresh(activity)
    return {"id": activity.id, "action": activity.action, "detail": activity.detail, "actor": activity.actor, "created_at": activity.created_at.isoformat() if activity.created_at else None}


@app.post("/api/assets", status_code=201)
def create_asset(body: AssetCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = Asset(
        name=body.name,
        hostname=body.hostname,
        ip=body.ip,
        kind=body.kind,
        risk=body.risk,
        status=body.status,
        operating_system=body.operating_system,
        owner=body.owner,
        software_json=body.software,
        last_assessment_date=body.last_assessment_date,
        notes=body.notes,
        metadata_json=body.metadata,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_dict(asset)


@app.get("/api/assets")
def list_assets(offset: int = 0, limit: int = 100, q: str | None = None, risk: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    if offset < 0 or limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="offset must be non-negative and limit must be between 1 and 500")
    query = db.query(Asset)
    if q:
        term = f"%{q.strip()}%"
        query = query.filter((Asset.name.ilike(term)) | (Asset.hostname.ilike(term)) | (Asset.ip.ilike(term)) | (Asset.owner.ilike(term)))
    if risk:
        query = query.filter(Asset.risk == risk)
    total = query.count()
    assets = query.order_by(Asset.id).offset(offset).limit(limit).all()
    return {"items": [_asset_dict(asset) for asset in assets], "total": total, "offset": offset, "limit": limit}


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    return _asset_dict(asset)


@app.put("/api/assets/{asset_id}")
@app.patch("/api/assets/{asset_id}")
def update_asset(asset_id: int, body: AssetUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    data = body.model_dump(exclude_unset=True)
    for field in ("name", "hostname", "ip", "kind", "risk", "status", "operating_system", "owner", "last_assessment_date", "notes"):
        if field in data:
            setattr(asset, field, data[field])
    if "software" in data:
        asset.software_json = data["software"]
    if "metadata" in data:
        asset.metadata_json = data["metadata"] or {}
    db.commit()
    db.refresh(asset)
    return _asset_dict(asset)


@app.delete("/api/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    db.delete(asset)
    db.commit()
    return {"deleted": True, "id": asset_id}


@app.post("/api/assets/{asset_id}/assess")
def assess_asset(asset_id: int, body: AssetAssessmentRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Run one explicitly authorized connectivity/HTTP metadata check.

    The target is always taken from the persisted asset; callers cannot supply
    an arbitrary destination or range.  The endpoint never reads response
    bodies, follows redirects, executes payloads, or performs exploit tests.
    """

    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="asset not found")
    target = _assessment_target(asset)
    started = datetime.now(timezone.utc).isoformat()
    if body.kind == "tcp":
        assert body.port is not None
        result = _tcp_metadata(target, body.port, body.timeout_seconds)
    else:
        result = _http_metadata(target, body.port, body.timeout_seconds)
    result.update({"asset_id": asset.id, "asset_name": asset.name, "kind": body.kind, "started_at": started, "authorized": True})
    asset.last_assessment_date = datetime.now(timezone.utc).isoformat()
    metadata = dict(asset.metadata_json or {})
    metadata["last_assessment"] = result
    asset.metadata_json = metadata
    analysis = AnalysisRecord(
        analysis_type="asset.assessment",
        input_value=target,
        source="local.authorized_assessment",
        explanation="Single-target assessment was explicitly authorized and limited to connectivity or HTTP response metadata.",
        result_json=result,
    )
    db.add(analysis)
    db.commit()
    result["analysis_id"] = analysis.id
    return result


@app.post("/api/assets/import", status_code=201)
async def import_assets(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    value, _filename, _content_type = await _request_value(request)
    try:
        _format, records = parse_log_input(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    created: list[Asset] = []
    for record in records:
        try:
            asset_data = AssetCreate.model_validate(record)
        except Exception as exc:
            raise HTTPException(status_code=422, detail="each imported asset needs a name") from exc
        asset = Asset(
            name=asset_data.name,
            hostname=asset_data.hostname,
            ip=asset_data.ip,
            kind=asset_data.kind,
            risk=asset_data.risk,
            status=asset_data.status,
            operating_system=asset_data.operating_system,
            owner=asset_data.owner,
            software_json=asset_data.software,
            last_assessment_date=asset_data.last_assessment_date,
            notes=asset_data.notes,
            metadata_json=asset_data.metadata,
        )
        db.add(asset)
        created.append(asset)
    db.commit()
    return {"imported": len(created), "items": [_asset_dict(asset) for asset in created]}


@app.post("/api/events/import", status_code=201)
async def import_events(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    value, _filename, _content_type = await _request_value(request)
    try:
        _format, records = parse_log_input(value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    events = [_event_from_record(record) for record in records]
    db.add_all(events)
    db.commit()
    return {"imported": len(events), "items": [_event_dict(event) for event in events]}


@app.get("/api/events")
def list_events(offset: int = 0, limit: int = 100, source: str | None = None, severity: str | None = None, event_type: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    if offset < 0 or limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail="offset must be non-negative and limit must be between 1 and 500")
    query = db.query(Event)
    if source:
        query = query.filter(Event.source == source)
    if severity:
        query = query.filter(Event.severity == severity)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    total = query.with_entities(func.count(Event.id)).scalar() or 0
    events = query.order_by(Event.id).offset(offset).limit(limit).all()
    return {"items": [_event_dict(event) for event in events], "total": total, "offset": offset, "limit": limit}


@app.get("/api/graph")
def graph(case_id: int | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return build_graph(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/graph.json")
def graph_json(case_id: int | None = None, db: Session = Depends(get_db)) -> Response:
    try:
        result = build_graph(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return JSONResponse(content=result, headers={"Content-Disposition": "attachment; filename=aegis-graph.json"})


@app.get("/api/graph/export")
def graph_export(case_id: int | None = None, db: Session = Depends(get_db)) -> Response:
    try:
        result = build_graph(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return JSONResponse(content=result, headers={"Content-Disposition": "attachment; filename=aegis-graph.json"})


@app.get("/api/graph/export.json")
def graph_export_json(case_id: int | None = None, db: Session = Depends(get_db)) -> Response:
    try:
        result = build_graph(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return JSONResponse(content=result, headers={"Content-Disposition": "attachment; filename=aegis-graph.json"})


@app.get("/api/reports/cases/{case_id}.json")
def case_report_json(case_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return build_case_report(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/api/reports/cases/{case_id}.csv")
def case_report_csv_endpoint(case_id: int, db: Session = Depends(get_db)) -> Response:
    try:
        report = build_case_report(db, case_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(content=case_report_csv(report), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.csv"})


@app.get("/api/reports/cases/{case_id}.pdf")
def case_report_pdf_endpoint(case_id: int, db: Session = Depends(get_db)) -> Response:
    try:
        report = build_case_report(db, case_id)
        pdf = case_report_pdf(report)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=case-{case_id}.pdf"})
