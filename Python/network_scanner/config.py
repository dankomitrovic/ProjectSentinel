"""
Project Sentinel configuration.

This module stores file locations and application settings.
Keeping them here means paths and settings only need to be changed once.
"""

# Network that Sentinel will scan.
# The current VirtualBox NAT network uses the 10.0.2.0/24 subnet.
TARGET_NETWORK = "10.0.2.0/24"

# Number of seconds Sentinel waits for ARP replies.
SCAN_TIMEOUT = 2

# Data file locations.
LATEST_SCAN_FILE = "data/latest_devices.csv"
SCAN_HISTORY_FILE = "data/scan_history.csv"
TRUSTED_DEVICES_FILE = "data/trusted_devices.csv"
PENDING_DEVICES_FILE = "data/pending_devices.csv"
DEVICE_REGISTRY_FILE = "data/device_registry.csv"