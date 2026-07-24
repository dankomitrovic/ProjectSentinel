"""
Project Sentinel event engine.

Stores an append-only security and audit event stream in JSON. The event
store is used by device timelines, alerts, reports and future integrations.
"""

import json
import os
import tempfile
from datetime import datetime
from threading import Lock

from config import EVENTS_FILE, MAX_EVENT_RECORDS
from logger import log_debug, log_warning


EVENT_LOCK = Lock()
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def normalise_mac_address(mac_address):
    return str(mac_address or "").strip().lower()


def current_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def ensure_event_store():
    parent_directory = os.path.dirname(EVENTS_FILE)

    if parent_directory:
        os.makedirs(parent_directory, exist_ok=True)

    if os.path.exists(EVENTS_FILE) and os.path.getsize(EVENTS_FILE) > 0:
        return

    _write_events_atomically([])


def _write_events_atomically(events):
    parent_directory = os.path.dirname(EVENTS_FILE) or "."
    os.makedirs(parent_directory, exist_ok=True)

    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix="sentinel_events_",
        suffix=".json",
        dir=parent_directory,
        text=True
    )

    try:
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8"
        ) as event_file:
            json.dump(events, event_file, indent=4)

        os.replace(temporary_path, EVENTS_FILE)

    except Exception:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
        raise


def load_events():
    ensure_event_store()

    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as event_file:
            events = json.load(event_file)

    except (OSError, json.JSONDecodeError) as error:
        log_warning(f"Unable to load Sentinel event store: {error}")
        return []

    if not isinstance(events, list):
        log_warning("Sentinel event store was not a JSON list")
        return []

    return events


def record_event(
    event_type,
    message,
    severity="INFO",
    device=None,
    metadata=None
):
    event_type = str(event_type).strip().upper()
    severity = str(severity).strip().upper()

    if severity not in VALID_SEVERITIES:
        severity = "INFO"

    device = device or {}
    metadata = metadata or {}

    event_device = {
        "friendly_name": str(
            device.get("friendly_name", "")
        ).strip(),
        "ip_address": str(
            device.get("ip_address", device.get("current_ip", ""))
        ).strip(),
        "mac_address": normalise_mac_address(
            device.get("mac_address", "")
        ),
        "hostname": str(
            device.get("hostname", "")
        ).strip()
    }

    with EVENT_LOCK:
        events = load_events()
        next_event_id = 1

        if events:
            next_event_id = max(
                int(event.get("id", 0))
                for event in events
            ) + 1

        event = {
            "id": next_event_id,
            "timestamp": current_timestamp(),
            "severity": severity,
            "type": event_type,
            "device": event_device,
            "message": str(message).strip(),
            "metadata": metadata
        }

        events.append(event)

        if MAX_EVENT_RECORDS > 0:
            events = events[-MAX_EVENT_RECORDS:]

        _write_events_atomically(events)

    log_debug(
        f"Recorded Sentinel event: id={event['id']}, "
        f"type={event_type}, severity={severity}"
    )

    return event


def get_recent_events(limit=50, severity=None, event_type=None):
    events = load_events()

    if severity:
        requested_severity = str(severity).strip().upper()
        events = [
            event
            for event in events
            if event.get("severity") == requested_severity
        ]

    if event_type:
        requested_type = str(event_type).strip().upper()
        events = [
            event
            for event in events
            if event.get("type") == requested_type
        ]

    events.sort(
        key=lambda event: event.get("timestamp", ""),
        reverse=True
    )

    return events[:max(0, int(limit))]


def get_device_events(mac_address, limit=100):
    requested_mac = normalise_mac_address(mac_address)

    events = [
        event
        for event in load_events()
        if normalise_mac_address(
            event.get("device", {}).get("mac_address", "")
        ) == requested_mac
    ]

    events.sort(
        key=lambda event: event.get("timestamp", ""),
        reverse=True
    )

    return events[:max(0, int(limit))]
