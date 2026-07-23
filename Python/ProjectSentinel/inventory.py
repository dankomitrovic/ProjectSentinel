"""
Project Sentinel device inventory.

This module manages trusted and pending devices.
Trust is never granted automatically.
"""

import csv
from datetime import datetime

from config import PENDING_DEVICES_FILE, TRUSTED_DEVICES_FILE
from logger import log_debug, log_info, log_warning


def load_trusted_devices():
    """
    Load the trusted-device inventory.

    Returns:
        A dictionary keyed by MAC address.
    """

    trusted_devices = {}

    with open(
        TRUSTED_DEVICES_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            mac_address = row["MAC Address"].strip().lower()

            if mac_address:
                trusted_devices[mac_address] = {
                    "friendly_name": row["Friendly Name"],
                    "owner": row["Owner"],
                    "device_type": row["Device Type"],
                    "trust_level": row["Trust Level"],
                    "notes": row["Notes"]
                }

    log_debug(
        f"Loaded {len(trusted_devices)} trusted device profile(s)"
    )

    return trusted_devices


def load_pending_mac_addresses():
    """
    Load MAC addresses that are already awaiting review.

    Returns:
        A set of pending MAC addresses.
    """

    pending_mac_addresses = set()

    with open(
        PENDING_DEVICES_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            mac_address = row["MAC Address"].strip().lower()

            if mac_address:
                pending_mac_addresses.add(mac_address)

    log_debug(
        f"Loaded {len(pending_mac_addresses)} pending device record(s)"
    )

    return pending_mac_addresses


def classify_devices(devices, trusted_devices, pending_mac_addresses):
    """
    Classify every currently visible device.

    Possible statuses:
        TRUSTED
        PENDING
        UNKNOWN

    Returns:
        A new list containing each device, its intelligence data,
        discovered services and inventory status.
    """

    classified_devices = []

    trusted_count = 0
    pending_count = 0
    unknown_count = 0

    for device in devices:
        mac_address = device["mac_address"].lower()

        classified_device = {
            "ip_address": device["ip_address"],
            "mac_address": mac_address,
            "hostname": device.get("hostname", "Unknown"),
            "vendor": device.get("vendor", "Unknown"),
            "detected_device_type": device.get(
                "detected_device_type",
                "Unknown"
            ),
            "detection_confidence": device.get(
                "detection_confidence",
                "Low"
            ),
            "detection_reason": device.get(
                "detection_reason",
                "Not available"
            ),
            "open_ports": device.get("open_ports", []),
            "status": "UNKNOWN",
            "friendly_name": "Unknown Device",
            "owner": "",
            "device_type": "",
            "trust_level": "",
            "notes": ""
        }

        if mac_address in trusted_devices:
            profile = trusted_devices[mac_address]

            classified_device["status"] = "TRUSTED"
            classified_device["friendly_name"] = profile["friendly_name"]
            classified_device["owner"] = profile["owner"]
            classified_device["device_type"] = profile["device_type"]
            classified_device["trust_level"] = profile["trust_level"]
            classified_device["notes"] = profile["notes"]

            trusted_count += 1

        elif mac_address in pending_mac_addresses:
            classified_device["status"] = "PENDING"
            pending_count += 1

        else:
            unknown_count += 1

        classified_devices.append(classified_device)

    log_debug(
        f"Device classification completed: "
        f"trusted={trusted_count}, "
        f"pending={pending_count}, "
        f"unknown={unknown_count}"
    )

    return classified_devices


def save_unknown_devices_to_pending(
    classified_devices,
    pending_mac_addresses
):
    """
    Add newly discovered unknown devices to the pending-review inventory.

    Trusted devices are ignored.
    Devices already pending are not added again.

    Returns:
        The number of newly added pending devices.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    added_count = 0

    with open(
        PENDING_DEVICES_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        for device in classified_devices:
            mac_address = device["mac_address"]

            if (
                device["status"] == "UNKNOWN"
                and mac_address not in pending_mac_addresses
            ):
                writer.writerow([
                    timestamp,
                    mac_address,
                    device["ip_address"],
                    "Pending Review"
                ])

                log_warning(
                    f"Unknown device added to pending review: "
                    f"name={device['friendly_name']}, "
                    f"hostname={device.get('hostname', 'Unknown')}, "
                    f"vendor={device.get('vendor', 'Unknown')}, "
                    f"detected_type="
                    f"{device.get('detected_device_type', 'Unknown')}, "
                    f"confidence="
                    f"{device.get('detection_confidence', 'Low')}, "
                    f"open_ports="
                    f"{len(device.get('open_ports', []))}, "
                    f"ip={device['ip_address']}, "
                    f"mac={mac_address}"
                )

                pending_mac_addresses.add(mac_address)
                device["status"] = "PENDING"
                added_count += 1

    if added_count > 0:
        log_info(
            f"Added {added_count} new device(s) to pending review"
        )
    else:
        log_debug("No new devices added to pending review")

    return added_count