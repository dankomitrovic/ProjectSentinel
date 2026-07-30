"""Detection and persistence engine for ESP32 sensor security events."""

import json
import os
from datetime import datetime
from threading import Lock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
EVENTS_FILE = os.path.join(DATA_DIR, "sensor_events.json")
EVENT_LOCK = Lock()
MAX_EVENTS = 2000
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _read_events():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(EVENTS_FILE):
        return []
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as handle:
            value = json.load(handle)
            return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _write_events(events):
    os.makedirs(DATA_DIR, exist_ok=True)
    temporary = f"{EVENTS_FILE}.tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(events[-MAX_EVENTS:], handle, indent=2, ensure_ascii=False)
    os.replace(temporary, EVENTS_FILE)


def _event(agent, event_type, severity, title, message, evidence=None, recommendation=""):
    return {
        "id": f"SE-{datetime.now().astimezone().strftime('%Y%m%d%H%M%S%f')}",
        "timestamp": _now(),
        "agent_id": agent.get("agent_id"),
        "agent_name": agent.get("name") or agent.get("agent_id"),
        "location": agent.get("location") or "Unassigned",
        "type": event_type,
        "severity": severity,
        "title": title,
        "message": message,
        "evidence": evidence or {},
        "recommendation": recommendation,
        "status": "OPEN",
    }


def detect_checkin_events(previous_agent, agent, telemetry, offline_threshold=90):
    """Create transition and anomaly events from one accepted check-in."""

    previous = (previous_agent or {}).get("latest") or {}
    events = []
    first_checkin = not previous_agent

    if first_checkin:
        events.append(_event(
            agent, "SENSOR_REGISTERED", "INFO", "Sensor node registered",
            f"{agent.get('name')} sent its first accepted heartbeat.",
            {"firmware": telemetry.get("firmware"), "ip_address": telemetry.get("ip_address")},
            "Confirm the node identity, location and expected firmware."
        ))
    else:
        last_seen = previous_agent.get("last_seen")
        try:
            age = (datetime.now().astimezone() - datetime.fromisoformat(str(last_seen).replace("Z", "+00:00")).astimezone()).total_seconds()
        except (TypeError, ValueError):
            age = 0
        if age > offline_threshold:
            events.append(_event(
                agent, "SENSOR_RECOVERED", "LOW", "Sensor node recovered",
                f"{agent.get('name')} resumed heartbeats after {int(age)} seconds.",
                {"offline_seconds": int(age)}, "Review the outage if it was unexpected."
            ))

    previous_motion = bool(previous.get("motion"))
    current_motion = bool(telemetry.get("motion"))
    if current_motion and not previous_motion:
        events.append(_event(
            agent, "MOTION_DETECTED", "MEDIUM", "Motion detected",
            f"The PIR sensor at {agent.get('location')} changed from clear to detected.",
            {"temperature": telemetry.get("temperature"), "humidity": telemetry.get("humidity")},
            "Confirm whether activity at this location is expected."
        ))
    elif previous_motion and not current_motion:
        events.append(_event(
            agent, "MOTION_CLEARED", "INFO", "Motion cleared",
            f"The PIR sensor at {agent.get('location')} returned to clear.",
            {}, "No action is required unless the preceding activity was unexpected."
        ))

    current_uptime = telemetry.get("uptime_seconds")
    previous_uptime = previous.get("uptime_seconds")
    restarted = (
        current_uptime is not None and previous_uptime is not None
        and current_uptime + 5 < previous_uptime
    )
    if restarted:
        events.append(_event(
            agent, "UNEXPECTED_RESTART", "HIGH", "Unexpected sensor restart",
            f"Agent uptime reset from {int(previous_uptime)} to {int(current_uptime)} seconds.",
            {"previous_uptime": previous_uptime, "current_uptime": current_uptime},
            "Inspect power, cabling and the device for an unexpected reset or tampering."
        ))

    current_rssi = telemetry.get("rssi")
    previous_rssi = previous.get("rssi")
    signal_drop = (
        current_rssi is not None and previous_rssi is not None
        and previous_rssi - current_rssi >= 15
    )
    if signal_drop:
        events.append(_event(
            agent, "WIFI_SIGNAL_DROP", "MEDIUM", "Abrupt Wi-Fi signal drop",
            f"Signal weakened by {int(previous_rssi-current_rssi)} dBm in one heartbeat.",
            {"previous_rssi": previous_rssi, "current_rssi": current_rssi},
            "Check whether the node was moved, obstructed or disconnected from its normal access point."
        ))

    temp = telemetry.get("temperature")
    prev_temp = previous.get("temperature")
    temp_bad = temp is not None and (temp < 5 or temp > 35)
    prev_temp_bad = prev_temp is not None and (prev_temp < 5 or prev_temp > 35)
    if temp_bad and not prev_temp_bad:
        severity = "CRITICAL" if temp < 0 or temp > 45 else "HIGH"
        events.append(_event(
            agent, "TEMPERATURE_ANOMALY", severity, "Temperature anomaly",
            f"Temperature entered an abnormal range at {temp}°C.",
            {"temperature": temp}, "Inspect the environment and verify the DHT22 reading."
        ))

    humidity = telemetry.get("humidity")
    prev_humidity = previous.get("humidity")
    humidity_bad = humidity is not None and (humidity < 20 or humidity > 75)
    prev_humidity_bad = prev_humidity is not None and (prev_humidity < 20 or prev_humidity > 75)
    if humidity_bad and not prev_humidity_bad:
        events.append(_event(
            agent, "HUMIDITY_ANOMALY", "HIGH", "Humidity anomaly",
            f"Humidity entered an abnormal range at {humidity}%.",
            {"humidity": humidity}, "Check ventilation, condensation and sensor placement."
        ))

    if current_motion and (restarted or signal_drop):
        reasons = []
        if restarted:
            reasons.append("device restart")
        if signal_drop:
            reasons.append("abrupt signal loss")
        events.append(_event(
            agent, "POSSIBLE_TAMPERING", "CRITICAL", "Possible physical tampering",
            "Motion coincided with " + " and ".join(reasons) + ".",
            {"motion": True, "restart": restarted, "signal_drop": signal_drop},
            "Inspect the node and its location immediately."
        ))

    if events:
        with EVENT_LOCK:
            stored = _read_events()
            stored.extend(events)
            _write_events(stored)
    return events


def list_sensor_events(limit=200, severity=None, agent_id=None):
    events = list(reversed(_read_events()))
    if severity:
        events = [item for item in events if item.get("severity") == str(severity).upper()]
    if agent_id:
        events = [item for item in events if item.get("agent_id") == agent_id]
    return events[:max(1, min(int(limit), 500))]


def sensor_event_summary(events=None):
    events = events if events is not None else list_sensor_events(limit=500)
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for item in events:
        severity = str(item.get("severity", "INFO")).upper()
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "total": len(events),
        "open": sum(1 for item in events if item.get("status") == "OPEN"),
        "counts": counts,
        "highest_severity": next((name for name in counts if counts[name]), "NONE"),
    }
