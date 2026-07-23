"""
Project Sentinel device registry.

The registry stores every device Sentinel has ever observed.

Unlike the pending and trusted files, the registry is not an approval
workflow. It is Sentinel's permanent memory of discovered devices.

The registry also stores the first established service baseline for
each device. Current service behaviour is compared against that
baseline before the registry is updated.
"""

import csv
import json
from datetime import datetime

from config import DEVICE_REGISTRY_FILE
from logger import log_debug
from risk_engine import calculate_risk_score


def safe_integer(value, default=0):
    """
    Convert a value into an integer.

    Returns the supplied default when the value is empty or invalid.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load_device_registry():
    """
    Load the existing device registry.

    Returns:
        A dictionary keyed by lowercase MAC address.

    Existing registry files without a Service Baseline column remain
    compatible. Their baseline will be established during a later scan.
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
            mac_address = row.get(
                "MAC Address",
                ""
            ).strip().lower()

            if not mac_address:
                continue

            registry[mac_address] = {
                "mac_address": mac_address,
                "current_ip": row.get(
                    "Current IP",
                    ""
                ),
                "friendly_name": row.get(
                    "Friendly Name",
                    "Unknown"
                ),
                "first_seen": row.get(
                    "First Seen",
                    ""
                ),
                "last_seen": row.get(
                    "Last Seen",
                    ""
                ),
                "times_seen": safe_integer(
                    row.get("Times Seen"),
                    0
                ),
                "status": row.get(
                    "Status",
                    "UNKNOWN"
                ),
                "owner": row.get(
                    "Owner",
                    ""
                ),
                "device_type": row.get(
                    "Device Type",
                    "Unknown"
                ),
                "risk_score": safe_integer(
                    row.get("Risk Score"),
                    0
                ),
                "risk_reasons": row.get(
                    "Risk Reasons",
                    "Status-based risk assessment"
                ),
                "service_baseline": row.get(
                    "Service Baseline",
                    ""
                ),
                "notes": row.get(
                    "Notes",
                    ""
                )
            }

    log_debug(
        f"Loaded {len(registry)} permanent registry record(s)"
    )

    return registry


def create_service_baseline(services):
    """
    Create stable JSON from the current service results.

    Only values useful for future behavioural comparison are retained.
    Volatile details such as response times, banners and connection
    attempts are deliberately excluded.
    """

    baseline_services = []

    sorted_services = sorted(
        services,
        key=lambda service: (
            service.get("port", 0),
            service.get("protocol", "TCP")
        )
    )

    for service in sorted_services:
        baseline_services.append({
            "port": service.get("port"),
            "protocol": service.get(
                "protocol",
                "TCP"
            ),
            "service": service.get(
                "service",
                "Unknown Service"
            ),
            "status": service.get(
                "status",
                "UNVERIFIED"
            ),
            "confidence": service.get(
                "confidence",
                "Low"
            )
        })

    return json.dumps(
        baseline_services,
        separators=(",", ":"),
        sort_keys=True
    )


def establish_service_baseline(device):
    """
    Create the initial service baseline for one device.

    An empty JSON list means a valid baseline was established and no
    candidate services were visible. An empty string means no baseline
    has yet been established.
    """

    services = device.get(
        "open_ports",
        []
    )

    return create_service_baseline(
        services
    )


def update_existing_registry_record(
    registry_record,
    device,
    timestamp,
    risk_score,
    risk_reasons_text
):
    """
    Update one existing permanent registry record.

    Returns:
        True when a new service baseline was established.
    """

    mac_address = device[
        "mac_address"
    ].lower()

    previous_ip = registry_record.get(
        "current_ip",
        ""
    )

    previous_status = registry_record.get(
        "status",
        "UNKNOWN"
    )

    previous_risk_score = registry_record.get(
        "risk_score",
        0
    )

    if previous_ip != device["ip_address"]:
        log_debug(
            f"Device IP changed for {mac_address}: "
            f"{previous_ip} -> {device['ip_address']}"
        )

    if previous_status != device["status"]:
        log_debug(
            f"Device status changed for {mac_address}: "
            f"{previous_status} -> {device['status']}"
        )

    if previous_risk_score != risk_score:
        log_debug(
            f"Device risk score changed for {mac_address}: "
            f"{previous_risk_score} -> {risk_score}"
        )

    registry_record["current_ip"] = device[
        "ip_address"
    ]

    registry_record["last_seen"] = timestamp

    registry_record["times_seen"] = (
        registry_record.get("times_seen", 0)
        + 1
    )

    registry_record["status"] = device[
        "status"
    ]

    registry_record["risk_score"] = risk_score

    registry_record[
        "risk_reasons"
    ] = risk_reasons_text

    registry_record[
        "friendly_name"
    ] = device.get(
        "friendly_name",
        "Unknown"
    )

    registry_record["owner"] = device.get(
        "owner",
        ""
    )

    registry_record[
        "device_type"
    ] = device.get(
        "device_type",
        "Unknown"
    )

    registry_record["notes"] = device.get(
        "notes",
        ""
    )

    baseline_established = False

    if not registry_record.get(
        "service_baseline"
    ):
        registry_record[
            "service_baseline"
        ] = establish_service_baseline(
            device
        )

        baseline_established = True

        log_debug(
            f"Established initial service baseline for "
            f"existing device: {mac_address}"
        )

    return baseline_established


def create_registry_record(
    device,
    timestamp,
    risk_score,
    risk_reasons_text
):
    """
    Create a new permanent registry record.
    """

    mac_address = device[
        "mac_address"
    ].lower()

    return {
        "mac_address": mac_address,
        "current_ip": device["ip_address"],
        "friendly_name": device.get(
            "friendly_name",
            "Unknown"
        ),
        "first_seen": timestamp,
        "last_seen": timestamp,
        "times_seen": 1,
        "status": device["status"],
        "owner": device.get(
            "owner",
            ""
        ),
        "device_type": device.get(
            "device_type",
            "Unknown"
        ),
        "risk_score": risk_score,
        "risk_reasons": risk_reasons_text,
        "service_baseline": (
            establish_service_baseline(device)
        ),
        "notes": device.get(
            "notes",
            ""
        )
    }


def update_device_registry(
    classified_devices,
    registry
):
    """
    Update Sentinel's permanent device memory.

    Behavioural comparison must occur before this function is called,
    because existing service baselines are deliberately preserved.

    Returns:
        The updated registry dictionary.
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    updated_count = 0
    created_count = 0
    baseline_count = 0

    for device in classified_devices:
        mac_address = device[
            "mac_address"
        ].lower()

        risk_score, risk_reasons = (
            calculate_risk_score(device)
        )

        risk_reasons_text = " | ".join(
            risk_reasons
        )

        if mac_address in registry:
            baseline_established = (
                update_existing_registry_record(
                    registry[mac_address],
                    device,
                    timestamp,
                    risk_score,
                    risk_reasons_text
                )
            )

            if baseline_established:
                baseline_count += 1

            updated_count += 1

            log_debug(
                f"Updated existing registry device: "
                f"mac={mac_address}, "
                f"risk={risk_score}"
            )

        else:
            registry[mac_address] = (
                create_registry_record(
                    device,
                    timestamp,
                    risk_score,
                    risk_reasons_text
                )
            )

            created_count += 1
            baseline_count += 1

            log_debug(
                f"Created permanent registry record: "
                f"mac={mac_address}, "
                f"ip={device['ip_address']}, "
                f"status={device['status']}, "
                f"risk={risk_score}"
            )

            log_debug(
                f"Established initial service baseline for "
                f"new device: {mac_address}"
            )

    log_debug(
        f"Registry update completed: "
        f"{updated_count} record(s) updated, "
        f"{created_count} record(s) created, "
        f"{baseline_count} service baseline(s) established"
    )

    return registry


def save_device_registry(registry):
    """
    Rewrite the permanent registry CSV.

    First-seen information and established service baselines remain
    preserved inside each registry record.
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
            "Risk Reasons",
            "Service Baseline",
            "Notes"
        ])

        for mac_address in sorted(
            registry.keys()
        ):
            device = registry[
                mac_address
            ]

            writer.writerow([
                device.get(
                    "mac_address",
                    mac_address
                ),
                device.get(
                    "current_ip",
                    ""
                ),
                device.get(
                    "friendly_name",
                    "Unknown"
                ),
                device.get(
                    "first_seen",
                    ""
                ),
                device.get(
                    "last_seen",
                    ""
                ),
                device.get(
                    "times_seen",
                    0
                ),
                device.get(
                    "status",
                    "UNKNOWN"
                ),
                device.get(
                    "owner",
                    ""
                ),
                device.get(
                    "device_type",
                    "Unknown"
                ),
                device.get(
                    "risk_score",
                    0
                ),
                device.get(
                    "risk_reasons",
                    "No risk reasons recorded"
                ),
                device.get(
                    "service_baseline",
                    ""
                ),
                device.get(
                    "notes",
                    ""
                )
            ])

    log_debug(
        f"Saved {len(registry)} permanent registry record(s) "
        f"to {DEVICE_REGISTRY_FILE}"
    )