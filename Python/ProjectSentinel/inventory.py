"""
Project Sentinel device inventory.

This module manages trusted and pending devices.
Trust is never granted automatically.
"""

import csv
import os
import tempfile
from datetime import datetime

from config import PENDING_DEVICES_FILE, TRUSTED_DEVICES_FILE
from events import record_event
from logger import log_debug, log_info, log_warning


TRUSTED_FIELDNAMES = [
    "MAC Address",
    "Friendly Name",
    "Owner",
    "Device Type",
    "Trust Level",
    "Notes"
]

PENDING_FIELDNAMES = [
    "Timestamp",
    "MAC Address",
    "IP Address",
    "Review Status"
]


def normalise_mac_address(mac_address):
    """
    Return a consistently formatted lowercase MAC address.
    """

    return str(mac_address).strip().lower()


def ensure_parent_directory(file_path):
    """
    Ensure the parent directory for a file exists.
    """

    parent_directory = os.path.dirname(file_path)

    if parent_directory:
        os.makedirs(parent_directory, exist_ok=True)


def ensure_csv_file(file_path, fieldnames):
    """
    Create a CSV file with the expected header if it does not exist.
    """

    ensure_parent_directory(file_path)

    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        return

    with open(
        file_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()


def write_csv_rows_atomically(file_path, fieldnames, rows):
    """
    Replace a CSV file safely using a temporary file.
    """

    ensure_parent_directory(file_path)

    directory = os.path.dirname(file_path) or "."

    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix="sentinel_",
        suffix=".csv",
        dir=directory,
        text=True
    )

    try:
        with os.fdopen(
            file_descriptor,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames,
                extrasaction="ignore"
            )

            writer.writeheader()
            writer.writerows(rows)

        os.replace(
            temporary_path,
            file_path
        )

    except Exception:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)

        raise


def load_trusted_device_rows():
    """
    Load all raw trusted-device CSV rows.
    """

    ensure_csv_file(
        TRUSTED_DEVICES_FILE,
        TRUSTED_FIELDNAMES
    )

    trusted_rows = []

    with open(
        TRUSTED_DEVICES_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            trusted_rows.append(
                {
                    "MAC Address": row.get(
                        "MAC Address",
                        ""
                    ).strip(),
                    "Friendly Name": row.get(
                        "Friendly Name",
                        ""
                    ).strip(),
                    "Owner": row.get(
                        "Owner",
                        ""
                    ).strip(),
                    "Device Type": row.get(
                        "Device Type",
                        ""
                    ).strip(),
                    "Trust Level": row.get(
                        "Trust Level",
                        ""
                    ).strip(),
                    "Notes": row.get(
                        "Notes",
                        ""
                    ).strip()
                }
            )

    return trusted_rows


def load_pending_device_rows():
    """
    Load all raw pending-device CSV rows.
    """

    ensure_csv_file(
        PENDING_DEVICES_FILE,
        PENDING_FIELDNAMES
    )

    pending_rows = []

    with open(
        PENDING_DEVICES_FILE,
        "r",
        newline="",
        encoding="utf-8"
    ) as file:
        reader = csv.DictReader(file)

        for row in reader:
            pending_rows.append(
                {
                    "Timestamp": row.get(
                        "Timestamp",
                        ""
                    ).strip(),
                    "MAC Address": row.get(
                        "MAC Address",
                        ""
                    ).strip(),
                    "IP Address": row.get(
                        "IP Address",
                        ""
                    ).strip(),
                    "Review Status": row.get(
                        "Review Status",
                        ""
                    ).strip()
                }
            )

    return pending_rows


def load_trusted_devices():
    """
    Load the trusted-device inventory.

    Returns:
        A dictionary keyed by MAC address.
    """

    trusted_devices = {}

    for row in load_trusted_device_rows():
        mac_address = normalise_mac_address(
            row["MAC Address"]
        )

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

    for row in load_pending_device_rows():
        mac_address = normalise_mac_address(
            row["MAC Address"]
        )

        if mac_address:
            pending_mac_addresses.add(
                mac_address
            )

    log_debug(
        f"Loaded {len(pending_mac_addresses)} pending device record(s)"
    )

    return pending_mac_addresses


def classify_devices(
    devices,
    trusted_devices,
    pending_mac_addresses
):
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
        mac_address = normalise_mac_address(
            device["mac_address"]
        )

        classified_device = {
            "ip_address": device["ip_address"],
            "mac_address": mac_address,
            "hostname": device.get(
                "hostname",
                "Unknown"
            ),
            "vendor": device.get(
                "vendor",
                "Unknown"
            ),
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
            "open_ports": device.get(
                "open_ports",
                []
            ),
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
            classified_device["friendly_name"] = profile[
                "friendly_name"
            ]
            classified_device["owner"] = profile[
                "owner"
            ]
            classified_device["device_type"] = profile[
                "device_type"
            ]
            classified_device["trust_level"] = profile[
                "trust_level"
            ]
            classified_device["notes"] = profile[
                "notes"
            ]

            trusted_count += 1

        elif mac_address in pending_mac_addresses:
            classified_device["status"] = "PENDING"
            pending_count += 1

        else:
            unknown_count += 1

        classified_devices.append(
            classified_device
        )

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
    Add newly discovered unknown devices to pending review.

    Trusted devices are ignored.
    Devices already pending are not added again.

    Returns:
        The number of newly added pending devices.
    """

    ensure_csv_file(
        PENDING_DEVICES_FILE,
        PENDING_FIELDNAMES
    )

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    added_count = 0

    with open(
        PENDING_DEVICES_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=PENDING_FIELDNAMES
        )

        for device in classified_devices:
            mac_address = normalise_mac_address(
                device["mac_address"]
            )

            if (
                device["status"] == "UNKNOWN"
                and mac_address not in pending_mac_addresses
            ):
                writer.writerow(
                    {
                        "Timestamp": timestamp,
                        "MAC Address": mac_address,
                        "IP Address": device["ip_address"],
                        "Review Status": "Pending Review"
                    }
                )

                log_warning(
                    f"Unknown device added to pending review: "
                    f"name={device['friendly_name']}, "
                    f"hostname="
                    f"{device.get('hostname', 'Unknown')}, "
                    f"vendor="
                    f"{device.get('vendor', 'Unknown')}, "
                    f"detected_type="
                    f"{device.get('detected_device_type', 'Unknown')}, "
                    f"confidence="
                    f"{device.get('detection_confidence', 'Low')}, "
                    f"open_ports="
                    f"{len(device.get('open_ports', []))}, "
                    f"ip={device['ip_address']}, "
                    f"mac={mac_address}"
                )

                pending_mac_addresses.add(
                    mac_address
                )

                device["status"] = "PENDING"
                added_count += 1

    if added_count > 0:
        log_info(
            f"Added {added_count} new device(s) to pending review"
        )

    else:
        log_debug(
            "No new devices added to pending review"
        )

    return added_count


def remove_device_from_pending(mac_address):
    """
    Remove a device from the pending-review inventory.

    Returns:
        True if at least one pending record was removed.
    """

    requested_mac = normalise_mac_address(
        mac_address
    )

    remaining_rows = []
    removed_count = 0

    for row in load_pending_device_rows():
        row_mac = normalise_mac_address(
            row["MAC Address"]
        )

        if row_mac == requested_mac:
            removed_count += 1

        else:
            remaining_rows.append(
                row
            )

    write_csv_rows_atomically(
        PENDING_DEVICES_FILE,
        PENDING_FIELDNAMES,
        remaining_rows
    )

    if removed_count > 0:
        log_info(
            f"Removed device from pending review: "
            f"mac={requested_mac}"
        )

    return removed_count > 0


def approve_device(
    mac_address,
    friendly_name,
    owner,
    device_type,
    trust_level,
    notes
):
    """
    Approve a device and save it in the trusted inventory.

    Existing trusted records are updated rather than duplicated.
    The device is removed from pending review after approval.

    Returns:
        The saved trusted-device profile.
    """

    requested_mac = normalise_mac_address(
        mac_address
    )

    friendly_name = str(
        friendly_name
    ).strip()

    owner = str(
        owner
    ).strip()

    device_type = str(
        device_type
    ).strip()

    trust_level = str(
        trust_level
    ).strip()

    notes = str(
        notes
    ).strip()

    if not requested_mac:
        raise ValueError(
            "A valid MAC address is required."
        )

    if not friendly_name:
        raise ValueError(
            "Friendly name is required."
        )

    if not owner:
        raise ValueError(
            "Owner is required."
        )

    if not device_type:
        raise ValueError(
            "Device type is required."
        )

    if not trust_level:
        trust_level = "Trusted"

    trusted_rows = load_trusted_device_rows()

    saved_row = {
        "MAC Address": requested_mac,
        "Friendly Name": friendly_name,
        "Owner": owner,
        "Device Type": device_type,
        "Trust Level": trust_level,
        "Notes": notes
    }

    updated_rows = []
    existing_record_found = False

    for row in trusted_rows:
        row_mac = normalise_mac_address(
            row["MAC Address"]
        )

        if row_mac == requested_mac:
            updated_rows.append(
                saved_row
            )

            existing_record_found = True

        else:
            updated_rows.append(
                row
            )

    if not existing_record_found:
        updated_rows.append(
            saved_row
        )

    write_csv_rows_atomically(
        TRUSTED_DEVICES_FILE,
        TRUSTED_FIELDNAMES,
        updated_rows
    )

    remove_device_from_pending(
        requested_mac
    )

    action = (
        "updated"
        if existing_record_found
        else "approved"
    )

    log_info(
        f"Trusted device {action}: "
        f"name={friendly_name}, "
        f"owner={owner}, "
        f"type={device_type}, "
        f"trust={trust_level}, "
        f"mac={requested_mac}"
    )

    record_event(
        event_type=(
            "DEVICE_APPROVED"
            if not existing_record_found
            else "DEVICE_PROFILE_UPDATED"
        ),
        severity="INFO",
        message=(
            "Device approved into the trusted inventory."
            if not existing_record_found
            else "Trusted device profile was updated."
        ),
        device={
            "mac_address": requested_mac,
            "friendly_name": friendly_name
        },
        metadata={
            "owner": owner,
            "device_type": device_type,
            "trust_level": trust_level,
            "notes": notes
        }
    )

    return {
        "mac_address": requested_mac,
        "friendly_name": friendly_name,
        "owner": owner,
        "device_type": device_type,
        "trust_level": trust_level,
        "notes": notes
    }