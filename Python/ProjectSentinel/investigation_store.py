"""Persistent investigation workflow for Project Sentinel sensor detections."""

import json
import os
from datetime import datetime
from threading import Lock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
INVESTIGATIONS_FILE = os.path.join(DATA_DIR, "investigations.json")
LOCK = Lock()
VALID_STATUSES = {"OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}
ACTIVE_STATUSES = {"OPEN", "ACKNOWLEDGED", "IN_PROGRESS"}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(INVESTIGATIONS_FILE):
        return []
    try:
        with open(INVESTIGATIONS_FILE, "r", encoding="utf-8") as handle:
            value = json.load(handle)
            return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write(items):
    os.makedirs(DATA_DIR, exist_ok=True)
    temporary = f"{INVESTIGATIONS_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(items, handle, indent=2, ensure_ascii=False)
    os.replace(temporary, INVESTIGATIONS_FILE)


def _next_id(items):
    highest = 0
    for item in items:
        value = str(item.get("id", ""))
        if value.startswith("INV-") and value[4:].isdigit():
            highest = max(highest, int(value[4:]))
    return f"INV-{highest + 1:06d}"


def _timeline_entry(entry_type, message, actor="Sentinel"):
    return {"timestamp": _now(), "type": entry_type, "message": message, "actor": actor}


def calculate_confidence(investigation):
    """Return a transparent 0-100 confidence score for an investigation."""
    detections = investigation.get("detections") or []
    evidence = investigation.get("evidence") or {}
    score = 35

    score += min(len(detections) * 8, 24)
    severities = {str(item.get("severity", "INFO")).upper() for item in detections}
    if "CRITICAL" in severities:
        score += 18
    elif "HIGH" in severities:
        score += 10

    detection_types = " ".join(str(item.get("type", "")).lower() for item in detections)
    titles = " ".join(str(item.get("title", "")).lower() for item in detections)
    combined = f"{detection_types} {titles}"
    for signal in ("motion", "restart", "rssi", "tamper"):
        if signal in combined:
            score += 5

    if evidence.get("motion") is True:
        score += 4
    if evidence.get("rssi") is not None:
        try:
            if float(evidence["rssi"]) <= -70:
                score += 4
        except (TypeError, ValueError):
            pass
    if evidence.get("uptime_seconds") is not None:
        try:
            if float(evidence["uptime_seconds"]) < 120:
                score += 5
        except (TypeError, ValueError):
            pass

    return min(max(score, 1), 99)


def create_or_correlate_investigation(detections, agent, telemetry):
    """Create one investigation for High/Critical detections or correlate into an open case."""
    qualifying = [item for item in detections if str(item.get("severity", "INFO")).upper() in {"HIGH", "CRITICAL"}]
    if not qualifying:
        return None

    agent_id = agent.get("agent_id")
    with LOCK:
        items = _read()
        active = next((item for item in reversed(items)
                       if item.get("agent_id") == agent_id
                       and item.get("status") in ACTIVE_STATUSES), None)
        detection_ids = [item.get("id") for item in qualifying if item.get("id")]
        highest = min((str(item.get("severity", "INFO")).upper() for item in qualifying), key=lambda x: SEVERITY_ORDER.get(x, 99))

        if active:
            known = set(active.get("detection_ids", []))
            new_ids = [value for value in detection_ids if value not in known]
            if new_ids:
                active.setdefault("detection_ids", []).extend(new_ids)
                active.setdefault("detections", []).extend(qualifying)
                if SEVERITY_ORDER.get(highest, 99) < SEVERITY_ORDER.get(active.get("severity", "INFO"), 99):
                    active["severity"] = highest
                active["updated_at"] = _now()
                active.setdefault("timeline", []).append(_timeline_entry(
                    "DETECTIONS_CORRELATED", f"Correlated {len(new_ids)} additional detection(s)."
                ))
                active["confidence"] = calculate_confidence(active)
                _write(items)
            return active

        primary = sorted(qualifying, key=lambda x: SEVERITY_ORDER.get(str(x.get("severity", "INFO")).upper(), 99))[0]
        now = _now()
        investigation = {
            "id": _next_id(items),
            "title": primary.get("title") or "Sensor security investigation",
            "description": primary.get("message") or "A sensor detection requires analyst review.",
            "status": "OPEN",
            "severity": highest,
            "agent_id": agent_id,
            "agent_name": agent.get("name") or agent_id,
            "location": agent.get("location") or "Unassigned",
            "assigned_to": "Unassigned",
            "created_at": now,
            "updated_at": now,
            "resolved_at": None,
            "detection_ids": detection_ids,
            "detections": qualifying,
            "evidence": {
                "temperature": telemetry.get("temperature"),
                "humidity": telemetry.get("humidity"),
                "motion": telemetry.get("motion"),
                "rssi": telemetry.get("rssi"),
                "uptime_seconds": telemetry.get("uptime_seconds"),
                "firmware": telemetry.get("firmware"),
                "ip_address": telemetry.get("ip_address"),
            },
            "notes": [],
            "timeline": [
                _timeline_entry("INVESTIGATION_CREATED", f"Investigation created from {len(qualifying)} high-priority detection(s)."),
            ],
        }
        investigation["confidence"] = calculate_confidence(investigation)
        items.append(investigation)
        _write(items)
        return investigation


def _enrich(item):
    enriched = dict(item)
    enriched["confidence"] = item.get("confidence") or calculate_confidence(item)
    return enriched


def list_investigations(status=None, severity=None, agent_id=None):
    items = [_enrich(item) for item in reversed(_read())]
    if status and status != "ALL":
        items = [item for item in items if item.get("status") == status]
    if severity and severity != "ALL":
        items = [item for item in items if item.get("severity") == severity]
    if agent_id and agent_id != "ALL":
        items = [item for item in items if item.get("agent_id") == agent_id]
    return items


def get_investigation(investigation_id):
    item = next((item for item in _read() if item.get("id") == investigation_id), None)
    return _enrich(item) if item else None


def get_related_investigations(investigation_id, agent_id, limit=5):
    """Return earlier cases for the same node, excluding the current case."""
    return [item for item in list_investigations(agent_id=agent_id) if item.get("id") != investigation_id][:limit]


def update_status(investigation_id, status, actor="Analyst"):
    status = str(status).upper().strip()
    if status not in VALID_STATUSES:
        raise ValueError("Unsupported investigation status.")
    with LOCK:
        items = _read()
        investigation = next((item for item in items if item.get("id") == investigation_id), None)
        if not investigation:
            raise ValueError("Investigation not found.")
        previous = investigation.get("status", "OPEN")
        investigation["status"] = status
        investigation["updated_at"] = _now()
        if status in {"RESOLVED", "CLOSED", "FALSE_POSITIVE"}:
            investigation["resolved_at"] = _now()
        elif previous in {"RESOLVED", "CLOSED", "FALSE_POSITIVE"}:
            investigation["resolved_at"] = None
        investigation.setdefault("timeline", []).append(_timeline_entry(
            "STATUS_CHANGED", f"Status changed from {previous} to {status}.", actor
        ))
        _write(items)
        return _enrich(investigation)


def add_note(investigation_id, note, author="Analyst"):
    note = str(note).strip()
    if not note:
        raise ValueError("A note is required.")
    with LOCK:
        items = _read()
        investigation = next((item for item in items if item.get("id") == investigation_id), None)
        if not investigation:
            raise ValueError("Investigation not found.")
        entry = {"timestamp": _now(), "author": str(author).strip() or "Analyst", "note": note}
        investigation.setdefault("notes", []).append(entry)
        investigation.setdefault("timeline", []).append(_timeline_entry("ANALYST_NOTE", note, entry["author"]))
        investigation["updated_at"] = _now()
        _write(items)
        return _enrich(investigation)


def investigation_summary(items=None):
    items = items if items is not None else list_investigations()
    now = datetime.now().astimezone()
    ages = []
    for item in items:
        if item.get("status") in ACTIVE_STATUSES:
            try:
                ages.append((now - datetime.fromisoformat(item["created_at"]).astimezone()).total_seconds())
            except (KeyError, TypeError, ValueError):
                pass
    return {
        "total": len(items),
        "open": sum(1 for item in items if item.get("status") in ACTIVE_STATUSES),
        "critical": sum(1 for item in items if item.get("severity") == "CRITICAL" and item.get("status") in ACTIVE_STATUSES),
        "in_progress": sum(1 for item in items if item.get("status") == "IN_PROGRESS"),
        "resolved": sum(1 for item in items if item.get("status") in {"RESOLVED", "CLOSED"}),
        "false_positive": sum(1 for item in items if item.get("status") == "FALSE_POSITIVE"),
        "average_age_minutes": round(sum(ages) / len(ages) / 60) if ages else 0,
    }
