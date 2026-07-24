"""
Project Sentinel configuration.

This module stores file locations and application settings.
"""

FALLBACK_TARGET_NETWORK = "10.0.2.0/24"
SCAN_TIMEOUT = 2
ENABLE_VENDOR_LOOKUP = True
UNKNOWN_VENDOR_NAME = "Unknown"

LATEST_SCAN_FILE = "data/latest_devices.csv"
SCAN_HISTORY_FILE = "data/scan_history.csv"
TRUSTED_DEVICES_FILE = "data/trusted_devices.csv"
PENDING_DEVICES_FILE = "data/pending_devices.csv"
DEVICE_REGISTRY_FILE = "data/device_registry.csv"
LATEST_SNAPSHOT_FILE = "data/latest_snapshot.json"
EVENTS_FILE = "data/events.json"

# Prevent unlimited event-file growth while keeping substantial history.
MAX_EVENT_RECORDS = 5000
