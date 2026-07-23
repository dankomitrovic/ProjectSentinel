"""
Project Sentinel risk-scoring engine.

This module calculates device risk using:

    - inventory approval status
    - exposed TCP services
    - service-validation status
    - higher-risk legacy and remote-access services
    - additional exposure on unapproved devices
    - false-positive protection for VirtualBox NAT infrastructure

The risk engine does not load or save registry files. It receives a
device record and returns a risk score with human-readable reasons.
"""


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


def normalise_inventory_status(status):
    """
    Return a supported inventory status.
    """

    normalised_status = str(
        status or "UNKNOWN"
    ).strip().upper()

    if normalised_status not in BASE_RISK_SCORES:
        return "UNKNOWN"

    return normalised_status


def normalise_service_status(status):
    """
    Return a supported service-validation status.
    """

    normalised_status = str(
        status or "UNVERIFIED"
    ).strip().upper()

    if normalised_status not in SERVICE_STATUS_MULTIPLIERS:
        return "UNVERIFIED"

    return normalised_status


def get_base_risk(status):
    """
    Return the base risk score for an inventory status.
    """

    normalised_status = normalise_inventory_status(
        status
    )

    return BASE_RISK_SCORES[normalised_status]


def get_service_risk_weight(port):
    """
    Return the configured risk weight for a TCP service port.

    Unlisted services receive a default weight of five points.
    """

    return SERVICE_RISK_WEIGHTS.get(port, 5)


def is_virtualbox_infrastructure(device):
    """
    Return True when a device appears to be VirtualBox NAT infrastructure.

    VirtualBox NAT endpoints may accept simple TCP connections without
    confirming that the expected application service is actually present.
    """

    ip_address = device.get(
        "ip_address",
        ""
    )

    friendly_name = str(
        device.get("friendly_name", "")
    ).lower()

    notes = str(
        device.get("notes", "")
    ).lower()

    detected_type = str(
        device.get(
            "detected_device_type",
            ""
        )
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


def calculate_service_risk(device, service):
    """
    Calculate the risk contribution from one detected service.

    Confirmed services receive their full configured weight. Probable
    and unverified services receive reduced weights.

    Returns:
        A tuple containing:
            service risk points
            human-readable risk reason
    """

    port = service.get("port")

    service_name = service.get(
        "service",
        "Unknown Service"
    )

    service_status = normalise_service_status(
        service.get("status")
    )

    confidence = str(
        service.get("confidence", "Low")
    )

    if (
        port == 445
        and service_status == "PROBABLE"
        and normalise_inventory_status(
            device.get("status")
        ) == "TRUSTED"
        and is_virtualbox_infrastructure(device)
    ):
        return (
            1,
            "Probable SMB result on trusted VirtualBox NAT "
            "infrastructure added minimal risk (+1)"
        )

    base_weight = get_service_risk_weight(
        port
    )

    multiplier = SERVICE_STATUS_MULTIPLIERS[
        service_status
    ]

    service_risk = round(
        base_weight * multiplier
    )

    if service_risk < 1:
        service_risk = 1

    reason = (
        f"{service_status.title()} {service_name} service "
        f"detected on {port}/TCP with "
        f"{confidence.lower()} confidence "
        f"(+{service_risk})"
    )

    return service_risk, reason


def calculate_risk_score(device):
    """
    Calculate a service-aware device risk score.

    Rules consider:

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

    status = normalise_inventory_status(
        device.get("status")
    )

    base_risk = get_base_risk(status)

    risk_score = base_risk

    risk_reasons = [
        f"{status.title()} inventory status established "
        f"base risk at {base_risk}"
    ]

    services = device.get(
        "open_ports",
        []
    )

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
        service_status = normalise_service_status(
            service.get("status")
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

        service_risk, service_reason = (
            calculate_service_risk(
                device,
                service
            )
        )

        risk_score += service_risk
        risk_reasons.append(service_reason)

    if (
        status in {"PENDING", "UNKNOWN"}
        and services
    ):
        exposure_increase = 5
        risk_score += exposure_increase

        risk_reasons.append(
            "Unapproved device exposes candidate services "
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

    risk_score = min(
        risk_score,
        100
    )

    return risk_score, risk_reasons