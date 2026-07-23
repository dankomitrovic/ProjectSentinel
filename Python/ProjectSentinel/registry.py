"""
Project Sentinel device registry.

The registry stores every device Sentinel has ever observed.

Unlike the pending and trusted files, the registry is not an approval
workflow. It is Sentinel's permanent memory of discovered devices.

The registry also stores the first established service baseline for
each device. Future monitoring phases can compare current services
against this baseline to identify behavioural changes.
"""

import csv
import json
from datetime import datetime

from config import DEVICE_REGISTRY_FILE
from logger import log_debug


BASE_RISK_SCORES = {
    "TRUSTED": 10,
    "PENDING": 60,
    "UNKNOWN": 80
}

SERVICE_RISK_WEIGHTS = {
    21: 20,
    22: 5,
    23: 30,
    25: 10,
    53: 3,
    80: 5,
    110: 15,
    139: 15,
    143: 10,
    443: 2,
    445: 15,
    554: 8,
    631: 5,
    993: 3,
    995: 3,
    1883: 12,
    3389: 20,
    5000: 8,
    5001: 5,
    5353: 2,
    8000: 8,
    8080: 8,
    8443: 5,
    8883: 5,
    9100: 8
}

SERVICE_STATUS_MULTIPLIERS = {
    "OPEN": 1.0,
    "PROBABLE": 0.4,
    "UNVERIFIED": 0.2
}

HIGH_RISK_PORTS = {
    21,
    23,
    110,
    139,
    445,
    1883,
    3389
}


def load_device_registry():
    """
    Load the existing device registry.

    Returns:
        A dictionary keyed by MAC address.

    Existing registry files without a Service Baseline column remain
    compatible. Their baseline will be established during the next scan.
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
                    "risk_reasons": row.get(
                        "Risk Reasons",
                        "Status-based risk assessment"
                    ),
                    "service_baseline": row.get(
                        "Service Baseline",
                        ""
                    ),
                    "notes": row["Notes"]
                }

    log_debug(
        f"Loaded {len(registry)} permanent registry record(s)"
    )

    return registry


def is_virtualbox_infrastructure(device):
    """
    Return True when a device appears to be VirtualBox NAT infrastructure.

    This prevents VirtualBox NAT connection behaviour from creating
    misleading high-risk service alerts.
    """

    ip_address = device.get("ip_address", "")
    friendly_name = device.get("friendly_name", "").lower()
    notes = device.get("notes", "").lower()
    detected_type = device.get(
        "detected_device_type",
        ""
    ).lower()

    return (
        ip_address in {
            "10.0.2.2",
            "10.0.2.3",
            "10.0.2.4"
        }
        and (
            "virtualbox" in friendly_name
            or "virtualbox" in notes
            or detected_type == "infrastructure"
        )
    )


def get_base_risk(status):
    """
    Return the base risk score for an inventory status.
    """

    return BASE_RISK_SCORES.get(
        status,
        BASE_RISK_SCORES["UNKNOWN"]
    )


def get_service_risk_weight(port):
    """
    Return the configured risk weight for a TCP service port.
    """

    return SERVICE_RISK_WEIGHTS.get(port, 5)


def create_service_baseline(services):
    """
    Create a stable JSON service baseline from current scan results.

    Only information useful for future behavioural comparisons is stored.
    Response times, banners and connection-attempt information are omitted
    because those values may change slightly during normal operation.

    Returns:
        A JSON string containing the service baseline.
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
            "protocol": service.get("protocol", "TCP"),
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

    An empty baseline is represented by an empty JSON list. This is
    different from an empty string, which means no baseline has yet
    been established.

    Returns:
        A JSON service-baseline string.
    """

    services = device.get("open_ports", [])

    return create_service_baseline(services)


def calculate_service_risk(device, service):
    """
    Calculate the risk contribution from one detected service.

    Confirmed services receive their full configured weight.
    Probable and unverified services receive reduced weight.

    Trusted VirtualBox NAT infrastructure receives only a minimal
    increase for probable port 445 results because VirtualBox may
    make simple TCP checks appear successful without confirming SMB.

    Returns:
        A tuple containing:
            service risk points
            human-readable risk reason
    """

    port = service.get("port")
    service_name = service.get("service", "Unknown Service")
    service_status = service.get("status", "UNVERIFIED")
    confidence = service.get("confidence", "Low")

    if (
        port == 445
        and service_status == "PROBABLE"
        and device.get("status") == "TRUSTED"
        and is_virtualbox_infrastructure(device)
    ):
        return (
            1,
            "Probable SMB result on trusted VirtualBox NAT "
            "infrastructure added minimal risk"
        )

    base_weight = get_service_risk_weight(port)

    multiplier = SERVICE_STATUS_MULTIPLIERS.get(
        service_status,
        SERVICE_STATUS_MULTIPLIERS["UNVERIFIED"]
    )

    service_risk = round(base_weight * multiplier)

    if service_risk < 1:
        service_risk = 1

    reason = (
        f"{service_status.title()} {service_name} service "
        f"detected on {port}/TCP with {confidence.lower()} confidence "
        f"(+{service_risk})"
    )

    return service_risk, reason


def calculate_risk_score(device):
    """
    Calculate a device risk score using status and detected services.

    Version 2 rules consider:

        - inventory status
        - confirmed, probable and unverified services
        - higher-risk legacy or remote-access services
        - additional exposure on pending or unknown devices
        - VirtualBox NAT false-positive protection

    Risk scores are capped at 100.

    Returns:
        A tuple containing:
            numeric risk score
            list of human-readable risk reasons
    """

    status = device.get("status", "UNKNOWN")
    base_risk = get_base_risk(status)

    risk_score = base_risk
    risk_reasons = [
        f"{status.title()} inventory status established "
        f"base risk at {base_risk}"
    ]

    services = device.get("open_ports", [])

    if not services:
        risk_reasons.append(
            "No candidate TCP services detected"
        )

        return risk_score, risk_reasons

    confirmed_service_count = 0
    probable_service_count = 0
    unverified_service_count = 0
    high_risk_service_count = 0

    for service in services:
        service_status = service.get(
            "status",
            "UNVERIFIED"
        )

        if service_status == "OPEN":
            confirmed_service_count += 1

        elif service_status == "PROBABLE":
            probable_service_count += 1

        else:
            unverified_service_count += 1

        port = service.get("port")

        if port in HIGH_RISK_PORTS:
            high_risk_service_count += 1

        service_risk, service_reason = calculate_service_risk(
            device,
            service
        )

        risk_score += service_risk
        risk_reasons.append(service_reason)

    if status in {"PENDING", "UNKNOWN"} and services:
        exposure_increase = 5

        risk_score += exposure_increase

        risk_reasons.append(
            f"Unapproved device exposes candidate services "
            f"(+{exposure_increase})"
        )

    if (
        status == "UNKNOWN"
        and high_risk_service_count > 0
    ):
        unknown_high_risk_increase = 5

        risk_score += unknown_high_risk_increase

        risk_reasons.append(
            f"Unknown device exposes "
            f"{high_risk_service_count} higher-risk service(s) "
            f"(+{unknown_high_risk_increase})"
        )

    risk_reasons.append(
        f"Service totals: "
        f"confirmed={confirmed_service_count}, "
        f"probable={probable_service_count}, "
        f"unverified={unverified_service_count}"
    )

    risk_score = min(risk_score, 100)

    return risk_score, risk_reasons


def update_device_registry(classified_devices, registry):
    """
    Update Sentinel's permanent memory using the current scan.

    Existing devices:
        - keep their original first-seen timestamp
        - receive a new last-seen timestamp
        - increase their times-seen count
        - receive updated inventory information
        - receive a recalculated service-aware risk score
        - receive a service baseline if one does not already exist

    New devices:
        - receive first-seen and last-seen timestamps
        - begin with a times-seen count of one
        - receive a service-aware risk score
        - receive an initial service baseline

    Existing non-empty baselines are deliberately preserved. Sentinel
    must not silently redefine normal behaviour during every scan.

    Returns:
        The updated registry dictionary.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    updated_count = 0
    created_count = 0
    baseline_count = 0

    for device in classified_devices:
        mac_address = device["mac_address"].lower()
        status = device["status"]

        risk_score, risk_reasons = calculate_risk_score(
            device
        )

        risk_reasons_text = " | ".join(risk_reasons)

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
            registry_record["risk_reasons"] = risk_reasons_text

            registry_record["friendly_name"] = device["friendly_name"]
            registry_record["owner"] = device["owner"]
            registry_record["device_type"] = device["device_type"]
            registry_record["notes"] = device["notes"]

            if not registry_record.get("service_baseline"):
                registry_record["service_baseline"] = (
                    establish_service_baseline(device)
                )

                baseline_count += 1

                log_debug(
                    f"Established initial service baseline for "
                    f"existing device: {mac_address}"
                )

            updated_count += 1

            log_debug(
                f"Updated existing registry device: "
                f"mac={mac_address}, "
                f"risk={risk_score}"
            )

        else:
            service_baseline = establish_service_baseline(
                device
            )

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
                "risk_reasons": risk_reasons_text,
                "service_baseline": service_baseline,
                "notes": device["notes"]
            }

            created_count += 1
            baseline_count += 1

            log_debug(
                f"Created permanent registry record: "
                f"mac={mac_address}, "
                f"ip={device['ip_address']}, "
                f"status={status}, "
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
    Replace the registry CSV with the updated permanent device records.

    The registry dictionary is rewritten after every monitoring cycle.
    First-seen information and established service baselines remain
    preserved inside each record.
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
                device.get(
                    "risk_reasons",
                    "No risk reasons recorded"
                ),
                device.get(
                    "service_baseline",
                    ""
                ),
                device["notes"]
            ])

    log_debug(
        f"Saved {len(registry)} permanent registry record(s) "
        f"to {DEVICE_REGISTRY_FILE}"
    )