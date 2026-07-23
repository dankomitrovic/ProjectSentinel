"""
Project Sentinel device registry.

The registry stores every device Sentinel has ever observed.

Unlike the pending and trusted files, the registry is not an approval
workflow. It is Sentinel's permanent memory of discovered devices.
"""

import csv
from datetime import datetime

from config import DEVICE_REGISTRY_FILE
from logger import log_debug


def load_device_registry():
    """
    Load the existing device registry.

    Returns:
        A dictionary keyed by MAC address.

    Using the MAC address as the dictionary key makes it fast to determine
    whether Sentinel has previously observed a device.
    """

    registry = {}

    with open(
        DEVICE_REGISTRY_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            mac_address = row["MAC Address"].strip().lower()

            if mac_address:
                registry[mac_address] = {
                    "mac_address": mac_address,
                    "current_ip": row["Current IP"],
                    "friendly_name": row["Friendly Name"],
                    "first_seen": row["First Seen"],
                    "last_seen": row["Last Seen"],
                    "times_seen": int(row["Times Seen"]),
                    "status": row["Status"],
                    "owner": row["Owner"],
                    "device_type": row["Device Type"],
                    "risk_score": int(row["Risk Score"]),
                    "notes": row["Notes"]
                }

    log_debug(
        f"Loaded {len(registry)} permanent registry record(s)"
    )

    return registry


def calculate_risk_score(status):
    """
    Assign an initial risk score based on inventory status.

    These are simple Version 1 rules.

    Future versions can also consider:
        - unusual ports
        - duplicate MAC addresses
        - behavioural changes
        - unexpected traffic
        - unusual operating hours
    """

    if status == "TRUSTED":
        return 10

    if status == "PENDING":
        return 60

    return 80


def update_device_registry(classified_devices, registry):
    """
    Update Sentinel's permanent memory using the current scan.

    Existing devices:
        - keep their original first-seen timestamp
        - receive a new last-seen timestamp
        - increase their times-seen count
        - receive updated inventory information

    New devices:
        - receive first-seen and last-seen timestamps
        - begin with a times-seen count of one

    Returns:
        The updated registry dictionary.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    updated_count = 0
    created_count = 0

    for device in classified_devices:
        mac_address = device["mac_address"].lower()
        status = device["status"]
        risk_score = calculate_risk_score(status)

        if mac_address in registry:
            registry_record = registry[mac_address]

            previous_ip = registry_record["current_ip"]
            previous_status = registry_record["status"]
            previous_risk_score = registry_record["risk_score"]

            if previous_ip != device["ip_address"]:
                log_debug(
                    f"Device IP changed for {mac_address}: "
                    f"{previous_ip} -> {device['ip_address']}"
                )

            if previous_status != status:
                log_debug(
                    f"Device status changed for {mac_address}: "
                    f"{previous_status} -> {status}"
                )

            if previous_risk_score != risk_score:
                log_debug(
                    f"Device risk score changed for {mac_address}: "
                    f"{previous_risk_score} -> {risk_score}"
                )

            registry_record["current_ip"] = device["ip_address"]
            registry_record["last_seen"] = timestamp
            registry_record["times_seen"] += 1
            registry_record["status"] = status
            registry_record["risk_score"] = risk_score

            registry_record["friendly_name"] = device["friendly_name"]
            registry_record["owner"] = device["owner"]
            registry_record["device_type"] = device["device_type"]
            registry_record["notes"] = device["notes"]

            updated_count += 1

            log_debug(
                f"Updated existing registry device: {mac_address}"
            )

        else:
            registry[mac_address] = {
                "mac_address": mac_address,
                "current_ip": device["ip_address"],
                "friendly_name": device["friendly_name"],
                "first_seen": timestamp,
                "last_seen": timestamp,
                "times_seen": 1,
                "status": status,
                "owner": device["owner"],
                "device_type": device["device_type"],
                "risk_score": risk_score,
                "notes": device["notes"]
            }

            created_count += 1

            log_debug(
                f"Created permanent registry record: "
                f"mac={mac_address}, "
                f"ip={device['ip_address']}, "
                f"status={status}, "
                f"risk={risk_score}"
            )

    log_debug(
        f"Registry update completed: "
        f"{updated_count} record(s) updated, "
        f"{created_count} record(s) created"
    )

    return registry


def save_device_registry(registry):
    """
    Replace the registry CSV with the updated permanent device records.

    The registry dictionary is rewritten after every monitoring cycle.
    First-seen information remains preserved inside each record.
    """

    with open(
        DEVICE_REGISTRY_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.writer(file)

        writer.writerow([
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
        ])

        # Sorting by MAC address produces stable and predictable output.
        for mac_address in sorted(registry.keys()):
            device = registry[mac_address]

            writer.writerow([
                device["mac_address"],
                device["current_ip"],
                device["friendly_name"],
                device["first_seen"],
                device["last_seen"],
                device["times_seen"],
                device["status"],
                device["owner"],
                device["device_type"],
                device["risk_score"],
                device["notes"]
            ])

    log_debug(
        f"Saved {len(registry)} permanent registry record(s) "
        f"to {DEVICE_REGISTRY_FILE}"
    )