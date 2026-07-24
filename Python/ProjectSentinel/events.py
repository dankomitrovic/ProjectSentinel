"""
Project Sentinel event management system.

Provides an append-only security and audit event stream stored in JSON.

The EventManager is responsible for:

- Event creation
- Event validation
- Atomic persistence
- Event identifiers
- Scan association
- Event retrieval
- Device timelines
- Store size limits

Compatibility wrapper functions are retained so existing Project Sentinel
modules can continue calling record_event(), get_recent_events() and
get_device_events().
"""

import json
import os
import tempfile
import uuid
from datetime import datetime
from threading import RLock

from config import EVENTS_FILE, MAX_EVENT_RECORDS
from logger import log_debug, log_warning


VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
}


def normalise_mac_address(mac_address):
    return str(mac_address or "").strip().lower()


def current_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


class EventManager:
    """
    Manages the Project Sentinel event store.

    Events retain the existing sequential numeric ``id`` field for
    compatibility and also receive a globally unique ``event_id`` value.

    The optional ``scan_id`` field allows events generated during the same
    network scan to be associated with one another.
    """

    def __init__(
        self,
        event_file=EVENTS_FILE,
        max_records=MAX_EVENT_RECORDS
    ):
        self.event_file = event_file
        self.max_records = self._normalise_max_records(max_records)
        self._lock = RLock()

        self.ensure_store()

    @staticmethod
    def _normalise_max_records(max_records):
        try:
            return max(0, int(max_records))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalise_limit(limit, default_limit):
        try:
            return max(0, int(limit))
        except (TypeError, ValueError):
            return default_limit

    @staticmethod
    def _normalise_event_type(event_type):
        normalised_type = str(event_type or "").strip().upper()

        if not normalised_type:
            return "GENERAL"

        return normalised_type

    @staticmethod
    def _normalise_severity(severity):
        normalised_severity = str(severity or "INFO").strip().upper()

        if normalised_severity not in VALID_SEVERITIES:
            return "INFO"

        return normalised_severity

    @staticmethod
    def _normalise_scan_id(scan_id):
        value = str(scan_id or "").strip()

        if not value:
            return None

        return value

    @staticmethod
    def _build_device_snapshot(device):
        device = device or {}

        return {
            "friendly_name": str(
                device.get("friendly_name", "")
            ).strip(),
            "ip_address": str(
                device.get(
                    "ip_address",
                    device.get("current_ip", "")
                )
            ).strip(),
            "mac_address": normalise_mac_address(
                device.get("mac_address", "")
            ),
            "hostname": str(
                device.get("hostname", "")
            ).strip()
        }

    @staticmethod
    def _normalise_metadata(metadata):
        if metadata is None:
            return {}

        if isinstance(metadata, dict):
            return metadata

        return {
            "value": metadata
        }

    def ensure_store(self):
        """
        Creates the event store when it does not already exist.
        """

        parent_directory = os.path.dirname(self.event_file)

        if parent_directory:
            os.makedirs(parent_directory, exist_ok=True)

        if (
            os.path.exists(self.event_file)
            and os.path.getsize(self.event_file) > 0
        ):
            return

        with self._lock:
            self._write_events_atomically([])

    def _write_events_atomically(self, events):
        """
        Writes events through a temporary file and atomically replaces the
        active event store.
        """

        parent_directory = os.path.dirname(self.event_file) or "."
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
                json.dump(
                    events,
                    event_file,
                    indent=4,
                    ensure_ascii=False
                )

                event_file.flush()
                os.fsync(event_file.fileno())

            os.replace(temporary_path, self.event_file)

        except Exception:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)

            raise

    def load_events(self):
        """
        Loads and validates the event store.
        """

        self.ensure_store()

        try:
            with open(
                self.event_file,
                "r",
                encoding="utf-8"
            ) as event_file:
                events = json.load(event_file)

        except (OSError, json.JSONDecodeError) as error:
            log_warning(
                f"Unable to load Sentinel event store: {error}"
            )
            return []

        if not isinstance(events, list):
            log_warning(
                "Sentinel event store was not a JSON list"
            )
            return []

        return [
            event
            for event in events
            if isinstance(event, dict)
        ]

    @staticmethod
    def _next_numeric_id(events):
        event_ids = []

        for event in events:
            try:
                event_ids.append(int(event.get("id", 0)))
            except (TypeError, ValueError):
                continue

        if not event_ids:
            return 1

        return max(event_ids) + 1

    def record_event(
        self,
        event_type,
        message,
        severity="INFO",
        device=None,
        metadata=None,
        scan_id=None
    ):
        """
        Creates and persists a Sentinel event.

        The numeric ``id`` field remains compatible with earlier releases.
        The ``event_id`` field is a globally unique identifier introduced in
        v0.8.
        """

        normalised_type = self._normalise_event_type(event_type)
        normalised_severity = self._normalise_severity(severity)
        normalised_scan_id = self._normalise_scan_id(scan_id)

        with self._lock:
            events = self.load_events()

            event = {
                "id": self._next_numeric_id(events),
                "event_id": str(uuid.uuid4()),
                "scan_id": normalised_scan_id,
                "timestamp": current_timestamp(),
                "severity": normalised_severity,
                "type": normalised_type,
                "device": self._build_device_snapshot(device),
                "message": str(message or "").strip(),
                "metadata": self._normalise_metadata(metadata)
            }

            events.append(event)

            if self.max_records > 0:
                events = events[-self.max_records:]

            self._write_events_atomically(events)

        log_debug(
            "Recorded Sentinel event: "
            f"id={event['id']}, "
            f"event_id={event['event_id']}, "
            f"type={normalised_type}, "
            f"severity={normalised_severity}, "
            f"scan_id={normalised_scan_id}"
        )

        return event

    def get_recent_events(
        self,
        limit=50,
        severity=None,
        event_type=None,
        scan_id=None
    ):
        """
        Returns the newest events, optionally filtered by severity, type or
        scan identifier.
        """

        events = self.load_events()

        if severity:
            requested_severity = self._normalise_severity(severity)

            events = [
                event
                for event in events
                if str(
                    event.get("severity", "")
                ).strip().upper() == requested_severity
            ]

        if event_type:
            requested_type = self._normalise_event_type(event_type)

            events = [
                event
                for event in events
                if str(
                    event.get("type", "")
                ).strip().upper() == requested_type
            ]

        if scan_id:
            requested_scan_id = self._normalise_scan_id(scan_id)

            events = [
                event
                for event in events
                if self._normalise_scan_id(
                    event.get("scan_id")
                ) == requested_scan_id
            ]

        events.sort(
            key=lambda event: event.get("timestamp", ""),
            reverse=True
        )

        requested_limit = self._normalise_limit(
            limit,
            default_limit=50
        )

        return events[:requested_limit]

    def get_device_events(self, mac_address, limit=100):
        """
        Returns events associated with a specific MAC address.
        """

        requested_mac = normalise_mac_address(mac_address)

        if not requested_mac:
            return []

        events = [
            event
            for event in self.load_events()
            if normalise_mac_address(
                event.get(
                    "device",
                    {}
                ).get(
                    "mac_address",
                    ""
                )
            ) == requested_mac
        ]

        events.sort(
            key=lambda event: event.get("timestamp", ""),
            reverse=True
        )

        requested_limit = self._normalise_limit(
            limit,
            default_limit=100
        )

        return events[:requested_limit]

    def get_scan_events(self, scan_id, limit=500):
        """
        Returns events associated with a specific scan.
        """

        requested_scan_id = self._normalise_scan_id(scan_id)

        if not requested_scan_id:
            return []

        events = [
            event
            for event in self.load_events()
            if self._normalise_scan_id(
                event.get("scan_id")
            ) == requested_scan_id
        ]

        events.sort(
            key=lambda event: event.get("timestamp", "")
        )

        requested_limit = self._normalise_limit(
            limit,
            default_limit=500
        )

        return events[:requested_limit]

    def get_event(self, event_identifier):
        """
        Finds an event using either its numeric id or unique event_id.
        """

        requested_identifier = str(
            event_identifier or ""
        ).strip()

        if not requested_identifier:
            return None

        for event in self.load_events():
            numeric_id = str(event.get("id", "")).strip()
            unique_id = str(event.get("event_id", "")).strip()

            if requested_identifier in {
                numeric_id,
                unique_id
            }:
                return event

        return None

    def count_events(
        self,
        severity=None,
        event_type=None,
        scan_id=None
    ):
        """
        Counts events using the same optional filters as recent-event
        retrieval.
        """

        events = self.get_recent_events(
            limit=self.max_records or 1000000,
            severity=severity,
            event_type=event_type,
            scan_id=scan_id
        )

        return len(events)


EVENT_MANAGER = EventManager()
EVENT_LOCK = EVENT_MANAGER._lock


def ensure_event_store():
    return EVENT_MANAGER.ensure_store()


def _write_events_atomically(events):
    with EVENT_MANAGER._lock:
        return EVENT_MANAGER._write_events_atomically(events)


def load_events():
    return EVENT_MANAGER.load_events()


def record_event(
    event_type,
    message,
    severity="INFO",
    device=None,
    metadata=None,
    scan_id=None
):
    return EVENT_MANAGER.record_event(
        event_type=event_type,
        message=message,
        severity=severity,
        device=device,
        metadata=metadata,
        scan_id=scan_id
    )


def get_recent_events(
    limit=50,
    severity=None,
    event_type=None,
    scan_id=None
):
    return EVENT_MANAGER.get_recent_events(
        limit=limit,
        severity=severity,
        event_type=event_type,
        scan_id=scan_id
    )


def get_device_events(mac_address, limit=100):
    return EVENT_MANAGER.get_device_events(
        mac_address=mac_address,
        limit=limit
    )


def get_scan_events(scan_id, limit=500):
    return EVENT_MANAGER.get_scan_events(
        scan_id=scan_id,
        limit=limit
    )


def get_event(event_identifier):
    return EVENT_MANAGER.get_event(event_identifier)


def count_events(
    severity=None,
    event_type=None,
    scan_id=None
):
    return EVENT_MANAGER.count_events(
        severity=severity,
        event_type=event_type,
        scan_id=scan_id
    )