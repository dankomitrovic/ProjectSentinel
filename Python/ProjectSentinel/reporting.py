"""
Project Sentinel console reporting.

This module controls how scan results and security information
are presented in the terminal.

It does not scan the network, modify inventories or save files.
"""

from version import get_banner


def display_banner():
    """
    Display the Project Sentinel application banner.

    Application identity and version information are supplied by
    version.py so they remain consistent throughout Sentinel.
    """

    print(get_banner())


def display_open_services(open_ports):
    """
    Display discovered TCP services for one device.
    """

    print()
    print("Detected Services")
    print("-" * 17)

    if not open_ports:
        print("None detected")
        return

    sorted_ports = sorted(
        open_ports,
        key=lambda service: service.get("port", 0)
    )

    for service in sorted_ports:
        port = service.get("port", "Unknown")
        protocol = service.get("protocol", "TCP")
        service_name = service.get("service", "Unknown")
        status = service.get("status", "UNVERIFIED")
        confidence = service.get("confidence", "Low")

        successful_attempts = service.get(
            "successful_attempts",
            0
        )

        total_attempts = service.get(
            "total_attempts",
            0
        )

        response_time = service.get(
            "response_time_ms"
        )

        banner_confirmed = service.get(
            "banner_confirmed",
            False
        )

        validation_reason = service.get(
            "validation_reason",
            "No validation information available"
        )

        banner = service.get("banner", "")

        print()
        print(f"Service       : {service_name}")
        print(f"Port          : {port}/{protocol}")
        print(f"Status        : {status}")
        print(f"Confidence    : {confidence}")
        print(
            f"Connections   : "
            f"{successful_attempts}/{total_attempts}"
        )

        if response_time is None:
            print("Response Time : Not available")
        else:
            print(
                f"Response Time : "
                f"{response_time} ms average"
            )

        if banner_confirmed:
            print("Banner Match  : Confirmed")
        else:
            print("Banner Match  : Not confirmed")

        print(f"Validation    : {validation_reason}")

        if banner:
            print(f"Banner        : {banner}")


def format_service_endpoint(service):
    """
    Return a readable service endpoint description.

    Example:
        445/TCP SMB
    """

    port = service.get("port", "Unknown")
    protocol = service.get("protocol", "TCP")
    service_name = service.get(
        "service",
        "Unknown Service"
    )

    return f"{port}/{protocol} {service_name}"


def display_behaviour_analysis(behaviour_analysis):
    """
    Display service behaviour compared with the stored baseline.
    """

    print()
    print("Service Behaviour")
    print("-" * 17)

    if not behaviour_analysis:
        print("Status        : Not analysed")
        return

    behaviour_status = behaviour_analysis.get(
        "behaviour_status",
        "UNKNOWN"
    )

    baseline_error = behaviour_analysis.get(
        "baseline_error",
        ""
    )

    print(f"Status        : {behaviour_status}")

    if behaviour_status == "NO_REGISTRY_RECORD":
        print("Comparison    : No permanent registry record available")
        return

    if behaviour_status == "NOT_ESTABLISHED":
        print("Comparison    : Service baseline not yet established")
        return

    if behaviour_status == "INVALID":
        print("Comparison    : Stored service baseline is invalid")

        if baseline_error:
            print(f"Error         : {baseline_error}")

        return

    baseline_service_count = behaviour_analysis.get(
        "baseline_service_count",
        0
    )

    current_service_count = behaviour_analysis.get(
        "current_service_count",
        0
    )

    change_count = behaviour_analysis.get(
        "change_count",
        0
    )

    print(
        f"Service Count : "
        f"{baseline_service_count} baseline / "
        f"{current_service_count} current"
    )

    print(f"Changes       : {change_count}")

    if behaviour_status == "UNCHANGED":
        print("Assessment    : Current services match baseline")
        return

    new_services = behaviour_analysis.get(
        "new_services",
        []
    )

    missing_services = behaviour_analysis.get(
        "missing_services",
        []
    )

    changed_services = behaviour_analysis.get(
        "changed_services",
        []
    )

    if new_services:
        print()
        print("New Services")

        for service in new_services:
            endpoint = format_service_endpoint(service)
            status = service.get("status", "UNVERIFIED")
            confidence = service.get("confidence", "LOW")

            print(
                f"  + {endpoint} "
                f"[{status}, {confidence}]"
            )

    if missing_services:
        print()
        print("Missing Services")

        for service in missing_services:
            endpoint = format_service_endpoint(service)
            status = service.get("status", "UNVERIFIED")
            confidence = service.get("confidence", "LOW")

            print(
                f"  - {endpoint} "
                f"[baseline: {status}, {confidence}]"
            )

    if changed_services:
        print()
        print("Changed Services")

        for comparison in changed_services:
            service_key = comparison.get(
                "service_key",
                "Unknown"
            )

            current_service = comparison.get(
                "current",
                {}
            )

            service_name = current_service.get(
                "service",
                "Unknown Service"
            )

            print(f"  * {service_key} {service_name}")

            for change in comparison.get(
                "changes",
                []
            ):
                field = change.get(
                    "field",
                    "value"
                ).title()

                previous_value = change.get(
                    "previous",
                    "Unknown"
                )

                current_value = change.get(
                    "current",
                    "Unknown"
                )

                direction = change.get(
                    "direction",
                    "CHANGED"
                )

                print(
                    f"      {field}: "
                    f"{previous_value} -> {current_value} "
                    f"({direction})"
                )


def display_devices(classified_devices):
    """
    Display every currently visible device and its inventory status.
    """

    print()
    print("=" * 60)
    print("CURRENT DEVICE INVENTORY")
    print("=" * 60)

    if not classified_devices:
        print("No devices responded to the network scan.")
        return

    device_number = 1

    for device in classified_devices:
        print()
        print("-" * 60)
        print(f"Device {device_number}")
        print("-" * 60)

        print(f"Name          : {device['friendly_name']}")
        print(
            f"Hostname      : "
            f"{device.get('hostname', 'Unknown')}"
        )

        print(
            f"Detected Type : "
            f"{device.get('detected_device_type', 'Unknown')}"
        )

        print(
            f"Confidence    : "
            f"{device.get('detection_confidence', 'Low')}"
        )

        print(
            f"Reason        : "
            f"{device.get('detection_reason', 'Not available')}"
        )

        print(f"IP Address    : {device['ip_address']}")
        print(f"MAC Address   : {device['mac_address']}")
        print(f"Vendor        : {device.get('vendor', 'Unknown')}")
        print(f"Status        : {device['status']}")

        if device["status"] == "TRUSTED":
            print(f"Owner         : {device['owner']}")
            print(f"Recorded Type : {device['device_type']}")
            print(f"Trust Level   : {device['trust_level']}")
            print(f"Notes         : {device['notes']}")

        elif device["status"] == "PENDING":
            print("Risk          : Review Required")
            print("Action        : Awaiting manual approval")

        else:
            print("Risk          : High")
            print("Action        : Investigate immediately")

        display_open_services(
            device.get("open_ports", [])
        )

        display_behaviour_analysis(
            device.get("behaviour_analysis", {})
        )

        device_number += 1


def display_changes(new_devices, missing_devices):
    """
    Display network changes detected since the previous scan.
    """

    print()
    print("=" * 60)
    print("NETWORK CHANGE DETECTION")
    print("=" * 60)

    if not new_devices and not missing_devices:
        print("No network changes detected.")
        return

    for device in new_devices:
        print()
        print("NEWLY VISIBLE DEVICE")
        print(
            f"Hostname      : "
            f"{device.get('hostname', 'Unknown')}"
        )

        print(
            f"Detected Type : "
            f"{device.get('detected_device_type', 'Unknown')}"
        )

        print(
            f"Confidence    : "
            f"{device.get('detection_confidence', 'Low')}"
        )

        print(f"IP Address    : {device['ip_address']}")
        print(f"MAC Address   : {device['mac_address']}")
        print(f"Vendor        : {device.get('vendor', 'Unknown')}")

        display_open_services(
            device.get("open_ports", [])
        )

    for device in missing_devices:
        print()
        print("DEVICE NO LONGER VISIBLE")
        print(
            f"Hostname      : "
            f"{device.get('hostname', 'Unknown')}"
        )

        print(
            f"Detected Type : "
            f"{device.get('detected_device_type', 'Unknown')}"
        )

        print(f"Previous IP   : {device['ip_address']}")
        print(f"MAC Address   : {device['mac_address']}")
        print(f"Vendor        : {device.get('vendor', 'Unknown')}")


def display_pending_result(added_count):
    """
    Report whether any devices were added to pending review.
    """

    print()
    print("=" * 60)
    print("PENDING REVIEW")
    print("=" * 60)

    if added_count == 0:
        print("No new devices were added to pending review.")
    else:
        print(
            f"{added_count} new device(s) added to "
            "data/pending_devices.csv"
        )


def determine_overall_risk(
    pending_count,
    unknown_count,
    new_device_count,
    missing_device_count,
    highest_device_risk,
    changed_behaviour_count
):
    """
    Determine Sentinel's overall risk level for the monitoring cycle.

    Rules:

    CRITICAL:
        At least one unknown device exists.

    HIGH:
        A device risk score is 80 or above.

    MEDIUM:
        Pending devices, network-presence changes or service-behaviour
        changes exist.

    LOW:
        All currently visible devices are trusted and no changes occurred.

    Returns:
        A text risk level.
    """

    if unknown_count > 0:
        return "CRITICAL"

    if highest_device_risk >= 80:
        return "HIGH"

    if (
        pending_count > 0
        or new_device_count > 0
        or missing_device_count > 0
        or changed_behaviour_count > 0
    ):
        return "MEDIUM"

    return "LOW"


def count_service_statuses(classified_devices):
    """
    Count service validation statuses across all visible devices.

    Returns:
        A dictionary containing OPEN, PROBABLE and UNVERIFIED counts.
    """

    counts = {
        "OPEN": 0,
        "PROBABLE": 0,
        "UNVERIFIED": 0
    }

    for device in classified_devices:
        for service in device.get("open_ports", []):
            status = service.get(
                "status",
                "UNVERIFIED"
            )

            if status in counts:
                counts[status] += 1
            else:
                counts["UNVERIFIED"] += 1

    return counts


def count_behaviour_results(classified_devices):
    """
    Count behavioural comparison results across visible devices.

    Returns:
        A dictionary containing device and service-change totals.
    """

    counts = {
        "CHANGED": 0,
        "UNCHANGED": 0,
        "UNAVAILABLE": 0,
        "NEW_SERVICES": 0,
        "MISSING_SERVICES": 0,
        "CHANGED_SERVICES": 0,
        "TOTAL_CHANGES": 0
    }

    for device in classified_devices:
        analysis = device.get(
            "behaviour_analysis",
            {}
        )

        behaviour_status = analysis.get(
            "behaviour_status",
            "UNKNOWN"
        )

        if behaviour_status == "CHANGED":
            counts["CHANGED"] += 1

        elif behaviour_status == "UNCHANGED":
            counts["UNCHANGED"] += 1

        else:
            counts["UNAVAILABLE"] += 1

        new_service_count = len(
            analysis.get("new_services", [])
        )

        missing_service_count = len(
            analysis.get("missing_services", [])
        )

        changed_service_count = len(
            analysis.get("changed_services", [])
        )

        counts["NEW_SERVICES"] += new_service_count
        counts["MISSING_SERVICES"] += missing_service_count
        counts["CHANGED_SERVICES"] += changed_service_count

        counts["TOTAL_CHANGES"] += (
            new_service_count
            + missing_service_count
            + changed_service_count
        )

    return counts


def display_security_summary(
    classified_devices,
    updated_registry,
    new_devices,
    missing_devices
):
    """
    Display a high-level security summary for the monitoring cycle.

    This gives the operator a quick overview before investigating
    individual device records.
    """

    trusted_count = 0
    pending_count = 0
    unknown_count = 0

    for device in classified_devices:
        if device["status"] == "TRUSTED":
            trusted_count += 1

        elif device["status"] == "PENDING":
            pending_count += 1

        else:
            unknown_count += 1

    service_counts = count_service_statuses(
        classified_devices
    )

    behaviour_counts = count_behaviour_results(
        classified_devices
    )

    total_candidate_services = (
        service_counts["OPEN"]
        + service_counts["PROBABLE"]
        + service_counts["UNVERIFIED"]
    )

    highest_device_risk = 0

    for device in classified_devices:
        mac_address = device["mac_address"]

        if mac_address in updated_registry:
            risk_score = updated_registry[
                mac_address
            ]["risk_score"]

            if risk_score > highest_device_risk:
                highest_device_risk = risk_score

    overall_risk = determine_overall_risk(
        pending_count,
        unknown_count,
        len(new_devices),
        len(missing_devices),
        highest_device_risk,
        behaviour_counts["CHANGED"]
    )

    print()
    print("=" * 60)
    print("SENTINEL SECURITY SUMMARY")
    print("=" * 60)

    print(f"Devices Visible       : {len(classified_devices)}")
    print(f"Trusted Devices       : {trusted_count}")
    print(f"Pending Review        : {pending_count}")
    print(f"Unknown Devices       : {unknown_count}")
    print(f"Candidate Services    : {total_candidate_services}")
    print(f"Confirmed Open        : {service_counts['OPEN']}")
    print(f"Probable Services     : {service_counts['PROBABLE']}")
    print(f"Unverified Services   : {service_counts['UNVERIFIED']}")
    print(f"Behaviour Changed     : {behaviour_counts['CHANGED']}")
    print(f"Behaviour Unchanged   : {behaviour_counts['UNCHANGED']}")
    print(f"Comparison Unavailable: {behaviour_counts['UNAVAILABLE']}")
    print(f"New Services          : {behaviour_counts['NEW_SERVICES']}")
    print(f"Missing Services      : {behaviour_counts['MISSING_SERVICES']}")
    print(f"Changed Services      : {behaviour_counts['CHANGED_SERVICES']}")
    print(f"Total Service Changes : {behaviour_counts['TOTAL_CHANGES']}")
    print(f"Newly Visible         : {len(new_devices)}")
    print(f"No Longer Visible     : {len(missing_devices)}")
    print(f"Highest Device Risk   : {highest_device_risk}")
    print(f"Overall Risk Level    : {overall_risk}")

    print()

    if overall_risk == "LOW":
        print(
            "Recommendation        : "
            "No immediate action required."
        )

    elif overall_risk == "MEDIUM":
        if behaviour_counts["CHANGED"] > 0:
            print(
                "Recommendation        : "
                "Review detected service-behaviour changes."
            )
        else:
            print(
                "Recommendation        : "
                "Review recent network changes."
            )

    elif overall_risk == "HIGH":
        print(
            "Recommendation        : "
            "Investigate high-risk devices."
        )

    else:
        print(
            "Recommendation        : "
            "Investigate immediately."
        )