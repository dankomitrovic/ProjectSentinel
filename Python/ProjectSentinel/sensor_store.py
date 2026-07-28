"""Persistent storage and presentation helpers for Sentinel sensor agents."""

import json
import os
from datetime import datetime, timezone
from threading import Lock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
AGENTS_FILE = os.path.join(DATA_DIR, "sensor_agents.json")
TELEMETRY_FILE = os.path.join(DATA_DIR, "sensor_telemetry.json")
STORE_LOCK = Lock()
MAX_TELEMETRY_RECORDS = 2000
ONLINE_THRESHOLD_SECONDS = 90


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read_json(path, default):
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
            return value
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path, value):
    os.makedirs(DATA_DIR, exist_ok=True)
    temporary_path = f"{path}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
    os.replace(temporary_path, path)


def _clean_text(value, maximum=120):
    return str(value or "").strip()[:maximum]


def _clean_number(value, minimum=None, maximum=None):
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return round(number, 2)


def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def register_agent(payload):
    agent_id = _clean_text(payload.get("agent_id") or payload.get("agent"), 64)
    if not agent_id:
        raise ValueError("agent_id is required")

    with STORE_LOCK:
        agents = _read_json(AGENTS_FILE, {})
        existing = agents.get(agent_id, {})
        created_at = existing.get("created_at") or _now()
        agent = {
            "agent_id": agent_id,
            "name": _clean_text(payload.get("name") or existing.get("name") or agent_id),
            "location": _clean_text(payload.get("location") or existing.get("location") or "Unassigned"),
            "description": _clean_text(payload.get("description") or existing.get("description"), 240),
            "firmware": _clean_text(payload.get("firmware") or existing.get("firmware") or "Unknown", 40),
            "created_at": created_at,
            "updated_at": _now(),
            "last_seen": existing.get("last_seen"),
            "enabled": bool(payload.get("enabled", existing.get("enabled", True))),
            "latest": existing.get("latest", {})
        }
        agents[agent_id] = agent
        _write_json(AGENTS_FILE, agents)
        return agent


def record_checkin(payload, remote_address=""):
    agent_id = _clean_text(payload.get("agent_id") or payload.get("agent"), 64)
    if not agent_id:
        raise ValueError("agent_id is required")

    timestamp = _now()
    motion_value = payload.get("motion")
    motion = motion_value if isinstance(motion_value, bool) else str(motion_value).lower() in {"1", "true", "yes", "detected"}

    telemetry = {
        "agent_id": agent_id,
        "timestamp": timestamp,
        "temperature": _clean_number(payload.get("temperature"), -50, 100),
        "humidity": _clean_number(payload.get("humidity"), 0, 100),
        "motion": motion,
        "rssi": _clean_number(payload.get("rssi"), -150, 0),
        "uptime_seconds": _clean_number(payload.get("uptime_seconds", payload.get("uptime")), 0),
        "relay_state": _clean_text(payload.get("relay_state") or payload.get("relay"), 20),
        "firmware": _clean_text(payload.get("firmware"), 40),
        "ip_address": _clean_text(payload.get("ip_address") or remote_address, 64)
    }

    with STORE_LOCK:
        agents = _read_json(AGENTS_FILE, {})
        existing = agents.get(agent_id, {})
        previous_motion = bool((existing.get("latest") or {}).get("motion", False))
        agent = {
            "agent_id": agent_id,
            "name": _clean_text(payload.get("name") or existing.get("name") or agent_id),
            "location": _clean_text(payload.get("location") or existing.get("location") or "Unassigned"),
            "description": _clean_text(existing.get("description"), 240),
            "firmware": telemetry["firmware"] or existing.get("firmware") or "Unknown",
            "created_at": existing.get("created_at") or timestamp,
            "updated_at": timestamp,
            "last_seen": timestamp,
            "enabled": existing.get("enabled", True),
            "latest": telemetry
        }
        agents[agent_id] = agent
        history = _read_json(TELEMETRY_FILE, [])
        history.append(telemetry)
        history = history[-MAX_TELEMETRY_RECORDS:]
        _write_json(AGENTS_FILE, agents)
        _write_json(TELEMETRY_FILE, history)

    return agent, telemetry, (motion and not previous_motion)


def list_agents():
    agents = _read_json(AGENTS_FILE, {})
    now = datetime.now().astimezone()
    output = []
    for agent in agents.values():
        item = dict(agent)
        last_seen = _parse_timestamp(item.get("last_seen"))
        age_seconds = None
        if last_seen is not None:
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            age_seconds = max(0, int((now - last_seen.astimezone()).total_seconds()))
        item["age_seconds"] = age_seconds
        item["online"] = bool(item.get("enabled", True) and age_seconds is not None and age_seconds <= ONLINE_THRESHOLD_SECONDS)
        output.append(item)
    output.sort(key=lambda item: (not item["online"], item.get("name", "").lower()))
    return output


def recent_telemetry(limit=100, agent_id=None):
    history = _read_json(TELEMETRY_FILE, [])
    if agent_id:
        history = [item for item in history if item.get("agent_id") == agent_id]
    return list(reversed(history[-max(1, min(int(limit), 500)):]))


def sensor_summary():
    agents = list_agents()
    latest_values = [item.get("latest", {}) for item in agents if item.get("latest")]
    temperatures = [item.get("temperature") for item in latest_values if item.get("temperature") is not None]
    humidities = [item.get("humidity") for item in latest_values if item.get("humidity") is not None]
    motions = [item for item in agents if (item.get("latest") or {}).get("motion")]
    return {
        "total_agents": len(agents),
        "online_agents": sum(1 for item in agents if item.get("online")),
        "offline_agents": sum(1 for item in agents if not item.get("online")),
        "average_temperature": round(sum(temperatures) / len(temperatures), 1) if temperatures else None,
        "average_humidity": round(sum(humidities) / len(humidities), 1) if humidities else None,
        "motion_agents": len(motions)
    }
