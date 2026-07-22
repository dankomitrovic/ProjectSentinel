"""
Project Sentinel storage operations.

This module manages CSV files used by Sentinel.
Other modules should not need to know how the information is stored.
"""

import csv
import os
from datetime import datetime

from config import (
    DEVICE_REGISTRY_FILE,
    LATEST_SCAN_FILE,
    PENDING_DEVICES_FILE,
    SCAN_HISTORY_FILE,
    TRUSTED_DEVICES_FILE
)


def ensure_data_files():
    """
    Create the data directory and required CSV files when they do not exist.
    """

    os.makedirs("data", exist_ok=True)

    # Each file has its own header structure.
    files_and_headers = {
        LATEST_SCAN_FILE: [
            "IP Address",
            "MAC Address"
        ],
        SCAN_HISTORY_FILE: [
            "Timestamp",
            "IP Address",
            "MAC Address"
        ],
        TRUSTED_DEVICES_FILE: [
            "MAC Address",
            "Friendly Name",
            "Owner",
            "Device Type",
            "Trust Level",
            "Notes"
        ],
        PENDING_DEVICES_FILE: [
            "Timestamp",
            "MAC Address",
            "IP Address",
            "Status"
        ],
        DEVICE_REGISTRY_FILE: [
            "MAC Address",
            "Current IP",
            "Friendly Name",
            "First Seen",
            "Last Seen",
            "Times Seen",
            "Status",
            "Owner",
            "Device Type",
            "Risk Score",
            "Notes"
        ]
    }

    # Only create files that do not already exist.
    # Existing information will not be overwritten.
    for file_path, headers in files_and_headers.items():
        if not os.path.exists(file_path):
            with open(file_path, "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(headers)


def load_latest_scan():
    """
    Load the devices recorded during the previous scan.

    Returns:
        A list of device dictionaries.
    """

    devices = []

    if not os.path.exists(LATEST_SCAN_FILE):
        return devices

    with open(LATEST_SCAN_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            devices.append({
                "ip_address": row["IP Address"],
                "mac_address": row["MAC Address"].lower()
            })

    return devices


def save_latest_scan(devices):
    """
    Replace the latest scan file with the current network state.
    """

    with open(LATEST_SCAN_FILE, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "IP Address",
            "MAC Address"
        ])

        for device in devices:
            writer.writerow([
                device["ip_address"],
                device["mac_address"]
            ])


def save_scan_history(devices):
    """
    Append the current scan to the permanent historical timeline.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(SCAN_HISTORY_FILE, "a", newline="") as file:
        writer = csv.writer(file)

        for device in devices:
            writer.writerow([
                timestamp,
                device["ip_address"],
                device["mac_address"]
            ])