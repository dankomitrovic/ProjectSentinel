"""
Project Sentinel risk-scoring engine.

This module calculates device risk using:

    - inventory approval status
    - exposed TCP services
    - service-validation status
    - higher-risk legacy and remote-access services
    - additional exposure on unapproved devices
    - behavioural changes from the permanent service baseline
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


CONFIDENCE_LEVELS = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


CONFIDENCE_BEHAVIOUR_MULTIPLIER = 0.1


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


def normalise_confidence(confidence):
    """
    Return a supported service confidence level.
    """

    normalised_confidence = str(
        confidence or "LOW"
    ).strip().upper()

    if normalised_confidence not in CONFIDENCE_LEVELS:
        return "LOW"

    return normalised_confidence


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


def calculate_weighted_service_risk(port, service_status):
    """
    Calculate service risk using its configured port weight and status.

    This helper is shared by normal exposure scoring and behavioural
    scoring so both use the same service-severity configuration.
    """

    normalised_status = normalise_service_status(
        service_status
    )

    base_weight = get_service_risk_weight(
        port
    )

    multiplier = SERVICE_STATUS_MULTIPLIERS[
        normalised_status
    ]

    service_risk = round(
        base_weight * multiplier
    )

    if service_risk < 1:
        service_risk = 1

    return service_risk


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

    service_risk = calculate_weighted_service_risk(
        port,
        service_status
    )

    reason = (
        f"{service_status.title()} {service_name} service "
        f"detected on {port}/TCP with "
        f"{confidence.lower()} confidence "
        f"(+{service_risk})"
    )

    return service_risk, reason


def calculate_behaviour_risk(device):
    """
    Calculate additional risk from service behaviour changes.

    New services reuse the existing service-risk weights.

    Increased service status adds the difference between the previous
    and current weighted service risk.

    Increased confidence adds ten percent of the service weight for
    each confidence level gained.

    Missing services and decreases do not increase risk.

    Returns:
        A tuple containing:
            behaviour risk points
            list of human-readable behaviour risk reasons
    """

    behaviour_analysis = device.get(
        "behaviour_analysis",
        {}
    )

    behaviour_status = str(
        behaviour_analysis.get(
            "behaviour_status",
            ""
        )
    ).strip().upper()

    if behaviour_status != "CHANGED":
        return 0, []

    behaviour_risk = 0
    behaviour_reasons = []

    new_services = behaviour_analysis.get(
        "new_services",
        []
    )

    changed_services = behaviour_analysis.get(
        "changed_services",
        []
    )

    for service in new_services:
        port = service.get("port")

        protocol = str(
            service.get("protocol", "TCP")
        ).upper()

        service_name = service.get(
            "service",
            "Unknown Service"
        )

        service_status = normalise_service_status(
            service.get("status")
        )

        new_service_risk = calculate_weighted_service_risk(
            port,
            service_status
        )

        behaviour_risk += new_service_risk

        behaviour_reasons.append(
            f"New {service_status.lower()} "
            f"{service_name} service appeared on "
            f"{port}/{protocol} "
            f"(+{new_service_risk})"
        )

    for service_comparison in changed_services:
        baseline_service = service_comparison.get(
            "baseline",
            {}
        )

        current_service = service_comparison.get(
            "current",
            {}
        )

        changes = service_comparison.get(
            "changes",
            []
        )

        port = current_service.get(
            "port",
            baseline_service.get("port")
        )

        protocol = str(
            current_service.get(
                "protocol",
                baseline_service.get(
                    "protocol",
                    "TCP"
                )
            )
        ).upper()

        service_name = current_service.get(
            "service",
            baseline_service.get(
                "service",
                "Unknown Service"
            )
        )

        service_weight = get_service_risk_weight(
            port
        )

        for change in changes:
            field = str(
                change.get("field", "")
            ).strip().lower()

            direction = str(
                change.get("direction", "")
            ).strip().upper()

            previous_value = change.get(
                "previous",
                ""
            )

            current_value = change.get(
                "current",
                ""
            )

            if (
                field == "status"
                and direction == "INCREASED"
            ):
                previous_status = normalise_service_status(
                    previous_value
                )

                current_status = normalise_service_status(
                    current_value
                )

                previous_risk = (
                    calculate_weighted_service_risk(
                        port,
                        previous_status
                    )
                )

                current_risk = (
                    calculate_weighted_service_risk(
                        port,
                        current_status
                    )
                )

                status_increase = max(
                    current_risk - previous_risk,
                    1
                )

                behaviour_risk += status_increase

                behaviour_reasons.append(
                    f"{service_name} on {port}/{protocol} "
                    f"increased from {previous_status} "
                    f"to {current_status} "
                    f"(+{status_increase})"
                )

            elif (
                field == "confidence"
                and direction == "INCREASED"
            ):
                previous_confidence = normalise_confidence(
                    previous_value
                )

                current_confidence = normalise_confidence(
                    current_value
                )

                confidence_levels_gained = (
                    CONFIDENCE_LEVELS[current_confidence]
                    - CONFIDENCE_LEVELS[
                        previous_confidence
                    ]
                )

                confidence_increase = max(
                    round(
                        service_weight
                        * CONFIDENCE_BEHAVIOUR_MULTIPLIER
                        * confidence_levels_gained
                    ),
                    1
                )

                behaviour_risk += confidence_increase

                behaviour_reasons.append(
                    f"{service_name} on {port}/{protocol} "
                    f"confidence increased from "
                    f"{previous_confidence} to "
                    f"{current_confidence} "
                    f"(+{confidence_increase})"
                )

    if behaviour_risk == 0:
        behaviour_reasons.append(
            "Behaviour changed, but only non-risk-increasing "
            "changes were detected"
        )

    return behaviour_risk, behaviour_reasons


def calculate_risk_score(device):
    """
    Calculate a service-aware and behaviour-aware device risk score.

    Rules consider:

        - inventory status
        - confirmed, probable and unverified services
        - higher-risk legacy or remote-access services
        - additional exposure on pending or unknown devices
        - behavioural changes from the permanent baseline
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

    confirmed_service_count = 0
    probable_service_count = 0
    unverified_service_count = 0
    high_risk_service_count = 0

    if not services:
        risk_reasons.append(
            "No candidate TCP services detected"
        )

    else:
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

        if status in {"PENDING", "UNKNOWN"}:
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

    behaviour_risk, behaviour_reasons = (
        calculate_behaviour_risk(
            device
        )
    )

    risk_score += behaviour_risk
    risk_reasons.extend(
        behaviour_reasons
    )

    if behaviour_risk > 0:
        risk_reasons.append(
            f"Behavioural changes added "
            f"{behaviour_risk} total risk point(s)"
        )

    risk_score = min(
        risk_score,
        100
    )

    return risk_score, risk_reasons