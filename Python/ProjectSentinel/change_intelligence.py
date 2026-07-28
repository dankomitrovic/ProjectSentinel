"""Project Sentinel v1.3.0 change intelligence presentation layer."""

from datetime import datetime, timedelta


CHANGE_EVENT_TYPES = {
    "DEVICE_DISCOVERED",
    "DEVICE_RETURNED",
    "DEVICE_MISSING",
    "DEVICE_OFFLINE",
    "SERVICE_CHANGED",
    "BEHAVIOUR_CHANGED",
    "RISK_CHANGED",
    "DEVICE_TRUST_REMOVED",
    "DEVICE_APPROVED",
}


def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _device_name(event):
    device = event.get("device") or {}
    return (
        device.get("friendly_name")
        or device.get("hostname")
        or device.get("ip_address")
        or device.get("mac_address")
        or "Network"
    )


def _change_label(event_type):
    labels = {
        "DEVICE_DISCOVERED": "New device",
        "DEVICE_RETURNED": "Device returned",
        "DEVICE_MISSING": "Device no longer visible",
        "DEVICE_OFFLINE": "Device offline",
        "SERVICE_CHANGED": "Service exposure changed",
        "BEHAVIOUR_CHANGED": "Behaviour changed",
        "RISK_CHANGED": "Risk score changed",
        "DEVICE_TRUST_REMOVED": "Trust removed",
        "DEVICE_APPROVED": "Asset approved",
    }
    return labels.get(event_type, event_type.replace("_", " ").title())


def build_change_intelligence(snapshot, recent_events, hours=24, max_items=8):
    """Return dashboard-ready network changes for the latest 24 hours."""

    now = datetime.now().astimezone()
    cutoff = now - timedelta(hours=hours)
    relevant = []

    for event in recent_events:
        event_type = str(event.get("type", "")).upper()
        if event_type not in CHANGE_EVENT_TYPES:
            continue

        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is not None and timestamp < cutoff:
            continue

        metadata = event.get("metadata") or {}
        relevant.append({
            "type": event_type,
            "label": _change_label(event_type),
            "severity": str(event.get("severity", "INFO")).upper(),
            "message": event.get("message", "Network state changed."),
            "timestamp": event.get("timestamp"),
            "device": event.get("device") or {},
            "device_name": _device_name(event),
            "metadata": metadata,
        })

    counts = {
        "new_devices": 0,
        "offline_devices": 0,
        "service_changes": 0,
        "risk_changes": 0,
        "trust_changes": 0,
    }

    for item in relevant:
        if item["type"] in {"DEVICE_DISCOVERED", "DEVICE_RETURNED"}:
            counts["new_devices"] += 1
        elif item["type"] in {"DEVICE_MISSING", "DEVICE_OFFLINE"}:
            counts["offline_devices"] += 1
        elif item["type"] in {"SERVICE_CHANGED", "BEHAVIOUR_CHANGED"}:
            counts["service_changes"] += 1
        elif item["type"] == "RISK_CHANGED":
            counts["risk_changes"] += 1
        elif item["type"] in {"DEVICE_TRUST_REMOVED", "DEVICE_APPROVED"}:
            counts["trust_changes"] += 1

    snapshot_changes = snapshot.get("network_changes", {}) or {}
    latest_new = len(snapshot_changes.get("new_devices", []) or [])
    latest_missing = len(snapshot_changes.get("missing_devices", []) or [])

    total = len(relevant)
    if total == 0 and latest_new == 0 and latest_missing == 0:
        status = "STABLE"
        headline = "No important changes detected"
        summary = "Sentinel has not recorded a meaningful network change in the last 24 hours."
    elif any(item["severity"] in {"HIGH", "CRITICAL"} for item in relevant):
        status = "ATTENTION"
        headline = "Important network changes need review"
        summary = f"Sentinel recorded {total} change event(s) in the last 24 hours."
    else:
        status = "CHANGED"
        headline = "Network changes were detected"
        summary = f"Sentinel recorded {total} change event(s) in the last 24 hours."

    return {
        "status": status,
        "headline": headline,
        "summary": summary,
        "window_hours": hours,
        "total": total,
        "counts": counts,
        "latest_scan_new": latest_new,
        "latest_scan_missing": latest_missing,
        "recent_changes": relevant[:max_items],
    }
