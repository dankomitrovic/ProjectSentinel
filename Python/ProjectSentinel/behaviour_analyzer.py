"""
Project Sentinel behavioural analysis.

This module compares a device's current service exposure against the
permanent service baseline stored in the device registry.

It identifies:

    - new services
    - missing services
    - service status changes
    - service confidence changes
    - unchanged service behaviour

This module does not modify the permanent baseline. Baseline updates
must always be deliberate so Sentinel does not silently redefine
abnormal behaviour as normal behaviour.
"""

import json

from logger import log_debug


SERVICE_STATUS_LEVELS = {
    "UNVERIFIED": 1,
    "PROBABLE": 2,
    "OPEN": 3
}

CONFIDENCE_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


def normalise_protocol(protocol):
    """
    Return a consistent uppercase protocol value.
    """

    if not protocol:
        return "TCP"

    return str(protocol).strip().upper()


def normalise_service_name(service_name):
    """
    Return a consistent service name.

    Unknown or blank names are represented as Unknown Service.
    """

    if not service_name:
        return "Unknown Service"

    return str(service_name).strip()


def normalise_status(status):
    """
    Return a supported service-validation status.
    """

    normalised_status = str(
        status or "UNVERIFIED"
    ).strip().upper()

    if normalised_status not in SERVICE_STATUS_LEVELS:
        return "UNVERIFIED"

    return normalised_status


def normalise_confidence(confidence):
    """
    Return a supported confidence level.
    """

    normalised_confidence = str(
        confidence or "Low"
    ).strip().upper()

    if normalised_confidence not in CONFIDENCE_LEVELS:
        return "LOW"

    return normalised_confidence


def create_service_key(service):
    """
    Create a stable key for matching a service between scans.

    Port and protocol identify the network endpoint. The displayed
    service name is not used as part of the key because service
    identification may improve over time.

    Returns:
        A string such as 445/TCP.
    """

    port = service.get("port")
    protocol = normalise_protocol(
        service.get("protocol", "TCP")
    )

    return f"{port}/{protocol}"


def normalise_service(service):
    """
    Convert one service record into the standard comparison format.
    """

    return {
        "port": service.get("port"),
        "protocol": normalise_protocol(
            service.get("protocol", "TCP")
        ),
        "service": normalise_service_name(
            service.get("service")
        ),
        "status": normalise_status(
            service.get("status")
        ),
        "confidence": normalise_confidence(
            service.get("confidence")
        )
    }


def create_service_map(services):
    """
    Convert a service list into a dictionary keyed by port/protocol.

    Invalid entries without a numeric port are ignored.
    """

    service_map = {}

    for service in services:
        normalised_service = normalise_service(service)
        port = normalised_service["port"]

        if not isinstance(port, int):
            continue

        service_key = create_service_key(
            normalised_service
        )

        service_map[service_key] = normalised_service

    return service_map


def load_service_baseline(registry_record):
    """
    Decode a service baseline stored in a registry record.

    Returns:
        A tuple containing:
            baseline service list
            baseline availability status
            baseline error message

    Baseline availability values:

        AVAILABLE
        NOT_ESTABLISHED
        INVALID
    """

    baseline_text = registry_record.get(
        "service_baseline",
        ""
    )

    if baseline_text is None:
        baseline_text = ""

    baseline_text = str(baseline_text).strip()

    if not baseline_text:
        return [], "NOT_ESTABLISHED", ""

    try:
        baseline_services = json.loads(
            baseline_text
        )
    except json.JSONDecodeError as error:
        return (
            [],
            "INVALID",
            f"Service baseline contains invalid JSON: {error}"
        )

    if not isinstance(baseline_services, list):
        return (
            [],
            "INVALID",
            "Service baseline must contain a JSON list"
        )

    return baseline_services, "AVAILABLE", ""


def determine_direction(
    previous_value,
    current_value,
    level_mapping
):
    """
    Determine whether a behavioural value increased or decreased.
    """

    previous_level = level_mapping.get(
        str(previous_value).upper(),
        0
    )

    current_level = level_mapping.get(
        str(current_value).upper(),
        0
    )

    if current_level > previous_level:
        return "INCREASED"

    if current_level < previous_level:
        return "DECREASED"

    return "UNCHANGED"


def compare_service_details(
    baseline_service,
    current_service
):
    """
    Compare matching baseline and current service records.

    Returns:
        A dictionary describing detected changes.
    """

    changes = []

    baseline_name = baseline_service["service"]
    current_name = current_service["service"]

    baseline_status = baseline_service["status"]
    current_status = current_service["status"]

    baseline_confidence = baseline_service["confidence"]
    current_confidence = current_service["confidence"]

    if baseline_name != current_name:
        changes.append({
            "field": "service",
            "previous": baseline_name,
            "current": current_name,
            "direction": "CHANGED"
        })

    if baseline_status != current_status:
        changes.append({
            "field": "status",
            "previous": baseline_status,
            "current": current_status,
            "direction": determine_direction(
                baseline_status,
                current_status,
                SERVICE_STATUS_LEVELS
            )
        })

    if baseline_confidence != current_confidence:
        changes.append({
            "field": "confidence",
            "previous": baseline_confidence,
            "current": current_confidence,
            "direction": determine_direction(
                baseline_confidence,
                current_confidence,
                CONFIDENCE_LEVELS
            )
        })

    return {
        "service_key": create_service_key(
            current_service
        ),
        "baseline": baseline_service,
        "current": current_service,
        "changes": changes
    }


def compare_services(
    baseline_services,
    current_services
):
    """
    Compare baseline services against current services.

    Returns:
        A behavioural comparison dictionary.
    """

    baseline_map = create_service_map(
        baseline_services
    )

    current_map = create_service_map(
        current_services
    )

    baseline_keys = set(baseline_map.keys())
    current_keys = set(current_map.keys())

    new_keys = sorted(
        current_keys - baseline_keys
    )

    missing_keys = sorted(
        baseline_keys - current_keys
    )

    matching_keys = sorted(
        baseline_keys & current_keys
    )

    new_services = [
        current_map[service_key]
        for service_key in new_keys
    ]

    missing_services = [
        baseline_map[service_key]
        for service_key in missing_keys
    ]

    changed_services = []
    unchanged_services = []

    for service_key in matching_keys:
        comparison = compare_service_details(
            baseline_map[service_key],
            current_map[service_key]
        )

        if comparison["changes"]:
            changed_services.append(
                comparison
            )
        else:
            unchanged_services.append(
                current_map[service_key]
            )

    change_count = (
        len(new_services)
        + len(missing_services)
        + len(changed_services)
    )

    if change_count == 0:
        behaviour_status = "UNCHANGED"
    else:
        behaviour_status = "CHANGED"

    return {
        "behaviour_status": behaviour_status,
        "change_count": change_count,
        "new_services": new_services,
        "missing_services": missing_services,
        "changed_services": changed_services,
        "unchanged_services": unchanged_services,
        "baseline_service_count": len(
            baseline_map
        ),
        "current_service_count": len(
            current_map
        )
    }


def create_unavailable_comparison(
    baseline_status,
    baseline_error=""
):
    """
    Create a standard result when comparison cannot be performed.
    """

    return {
        "behaviour_status": baseline_status,
        "change_count": 0,
        "new_services": [],
        "missing_services": [],
        "changed_services": [],
        "unchanged_services": [],
        "baseline_service_count": 0,
        "current_service_count": 0,
        "baseline_error": baseline_error
    }


def analyse_device_behaviour(
    device,
    registry
):
    """
    Compare one currently discovered device with its registry baseline.

    The comparison result is added to the device under:

        behaviour_analysis

    Returns:
        The updated device dictionary.
    """

    mac_address = device.get(
        "mac_address",
        ""
    ).lower()

    registry_record = registry.get(
        mac_address
    )

    if not registry_record:
        device["behaviour_analysis"] = (
            create_unavailable_comparison(
                "NO_REGISTRY_RECORD"
            )
        )

        log_debug(
            f"Behaviour comparison unavailable for "
            f"{mac_address}: no registry record"
        )

        return device

    (
        baseline_services,
        baseline_status,
        baseline_error
    ) = load_service_baseline(
        registry_record
    )

    if baseline_status != "AVAILABLE":
        device["behaviour_analysis"] = (
            create_unavailable_comparison(
                baseline_status,
                baseline_error
            )
        )

        log_debug(
            f"Behaviour comparison unavailable for "
            f"{mac_address}: {baseline_status}"
        )

        return device

    current_services = device.get(
        "open_ports",
        []
    )

    comparison = compare_services(
        baseline_services,
        current_services
    )

    comparison["baseline_error"] = ""

    device["behaviour_analysis"] = comparison

    log_debug(
        f"Behaviour comparison completed for "
        f"{mac_address}: "
        f"status={comparison['behaviour_status']}, "
        f"changes={comparison['change_count']}, "
        f"new={len(comparison['new_services'])}, "
        f"missing={len(comparison['missing_services'])}, "
        f"changed={len(comparison['changed_services'])}"
    )

    return device


def analyse_device_behaviours(
    classified_devices,
    registry
):
    """
    Analyse behaviour for all currently discovered devices.

    Returns:
        The updated classified device list.
    """

    analysed_devices = []

    changed_device_count = 0
    unchanged_device_count = 0
    unavailable_device_count = 0

    log_debug(
        f"Starting behavioural comparison for "
        f"{len(classified_devices)} device(s)"
    )

    for device in classified_devices:
        analysed_device = analyse_device_behaviour(
            device,
            registry
        )

        analysed_devices.append(
            analysed_device
        )

        behaviour_status = analysed_device.get(
            "behaviour_analysis",
            {}
        ).get(
            "behaviour_status",
            "UNKNOWN"
        )

        if behaviour_status == "CHANGED":
            changed_device_count += 1

        elif behaviour_status == "UNCHANGED":
            unchanged_device_count += 1

        else:
            unavailable_device_count += 1

    log_debug(
        f"Behavioural comparison completed: "
        f"changed={changed_device_count}, "
        f"unchanged={unchanged_device_count}, "
        f"unavailable={unavailable_device_count}"
    )

    return analysed_devices