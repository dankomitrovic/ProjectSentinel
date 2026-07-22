"""
Project Sentinel device inventory.

This module manages trusted and pending devices.
Trust is never granted automatically.
"""

import csv
from datetime import datetime

from config import PENDING_DEVICES_FILE, TRUSTED_DEVICES_FILE


def load_trusted_devices():
    """
    Load the trusted-device inventory.

    Returns:
        A dictionary keyed by MAC address.

    Using the MAC address as the key allows Sentinel to quickly retrieve
    the complete profile for a trusted device.
    """

    trusted_devices = {}

    with open(TRUSTED_DEVICES_FILE, "r", newline="") as file:
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

    return trusted_devices


def load_pending_mac_addresses():
    """
    Load MAC addresses that are already awaiting review.

    Returns:
        A set of pending MAC addresses.

    A set prevents Sentinel from adding the same device repeatedly.
    """

    pending_mac_addresses = set()

    with open(PENDING_DEVICES_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            mac_address = row["MAC Address"].strip().lower()

            if mac_address:
                pending_mac_addresses.add(mac_address)

    return pending_mac_addresses


def classify_devices(devices, trusted_devices, pending_mac_addresses):
    """
    Classify every currently visible device.

    Possible statuses:
        TRUSTED
        PENDING
        UNKNOWN

    Returns:
        A new list containing each device and its inventory status.
    """

    classified_devices = []

    for device in devices:
        mac_address = device["mac_address"].lower()

        classified_device = {
            "ip_address": device["ip_address"],
            "mac_address": mac_address,
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

        elif mac_address in pending_mac_addresses:
            classified_device["status"] = "PENDING"

        classified_devices.append(classified_device)

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

    with open(PENDING_DEVICES_FILE, "a", newline="") as file:
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

                pending_mac_addresses.add(mac_address)
                device["status"] = "PENDING"
                added_count += 1

    return added_count