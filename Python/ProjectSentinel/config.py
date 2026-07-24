"""
Project Sentinel configuration.

This module stores file locations and application settings.
Keeping them here means paths and settings only need to be changed once.
"""

# Fallback network used only when automatic detection fails.
FALLBACK_TARGET_NETWORK = "10.0.2.0/24"

# Number of seconds Sentinel waits for ARP replies.
SCAN_TIMEOUT = 2

# Device-intelligence features.
ENABLE_VENDOR_LOOKUP = True

# Text used when a MAC vendor cannot be identified.
UNKNOWN_VENDOR_NAME = "Unknown"

# Data file locations.
LATEST_SCAN_FILE = "data/latest_devices.csv"
SCAN_HISTORY_FILE = "data/scan_history.csv"
TRUSTED_DEVICES_FILE = "data/trusted_devices.csv"
PENDING_DEVICES_FILE = "data/pending_devices.csv"
DEVICE_REGISTRY_FILE = "data/device_registry.csv"
LATEST_SNAPSHOT_FILE = "data/latest_snapshot.json"