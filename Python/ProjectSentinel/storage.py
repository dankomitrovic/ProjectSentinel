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

from logger import log_debug, log_info


def ensure_data_files():
    """
    Create the data directory and required CSV files when they do not exist.
    """

    os.makedirs("data", exist_ok=True)
    log_debug("Data directory verified")

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

    created_count = 0

    # Only create files that do not already exist.
    # Existing information will not be overwritten.
    for file_path, headers in files_and_headers.items():
        if not os.path.exists(file_path):
            with open(file_path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(headers)

            created_count += 1
            log_info(f"Created missing storage file: {file_path}")

        else:
            log_debug(f"Storage file verified: {file_path}")

    log_debug(
        f"Storage verification completed with "
        f"{created_count} file(s) created"
    )


def load_latest_scan():
    """
    Load the devices recorded during the previous scan.

    Returns:
        A list of device dictionaries.
    """

    devices = []

    if not os.path.exists(LATEST_SCAN_FILE):
        log_debug(
            f"Latest scan file not found: {LATEST_SCAN_FILE}"
        )
        return devices

    with open(
        LATEST_SCAN_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            devices.append({
                "ip_address": row["IP Address"],
                "mac_address": row["MAC Address"].lower()
            })

    log_debug(
        f"Loaded {len(devices)} previous device record(s) "
        f"from {LATEST_SCAN_FILE}"
    )

    return devices


def save_latest_scan(devices):
    """
    Replace the latest scan file with the current network state.
    """

    with open(
        LATEST_SCAN_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
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

    log_debug(
        f"Saved latest scan with {len(devices)} device record(s) "
        f"to {LATEST_SCAN_FILE}"
    )


def save_scan_history(devices):
    """
    Append the current scan to the permanent historical timeline.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(
        SCAN_HISTORY_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        for device in devices:
            writer.writerow([
                timestamp,
                device["ip_address"],
                device["mac_address"]
            ])

    log_debug(
        f"Appended {len(devices)} device record(s) "
        f"to {SCAN_HISTORY_FILE}"
    )