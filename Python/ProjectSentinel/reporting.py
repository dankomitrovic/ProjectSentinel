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
    print("Open Services")
    print("-" * 13)

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

        print(f"{port}/{protocol:<5} {service_name}")


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
        print(f"Hostname      : {device.get('hostname', 'Unknown')}")
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
        print(f"Hostname      : {device.get('hostname', 'Unknown')}")
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
        print(f"Hostname      : {device.get('hostname', 'Unknown')}")
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
    highest_device_risk
):
    """
    Determine Sentinel's overall risk level for the monitoring cycle.

    Version 1 rules:

    CRITICAL:
        At least one unknown device exists.

    HIGH:
        A device risk score is 80 or above.

    MEDIUM:
        Pending devices, newly visible devices or missing devices exist.

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
    ):
        return "MEDIUM"

    return "LOW"


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
    total_open_ports = 0

    for device in classified_devices:
        if device["status"] == "TRUSTED":
            trusted_count += 1

        elif device["status"] == "PENDING":
            pending_count += 1

        else:
            unknown_count += 1

        total_open_ports += len(
            device.get("open_ports", [])
        )

    highest_device_risk = 0

    for device in classified_devices:
        mac_address = device["mac_address"]

        if mac_address in updated_registry:
            risk_score = updated_registry[mac_address]["risk_score"]

            if risk_score > highest_device_risk:
                highest_device_risk = risk_score

    overall_risk = determine_overall_risk(
        pending_count,
        unknown_count,
        len(new_devices),
        len(missing_devices),
        highest_device_risk
    )

    print()
    print("=" * 60)
    print("SENTINEL SECURITY SUMMARY")
    print("=" * 60)

    print(f"Devices Visible       : {len(classified_devices)}")
    print(f"Trusted Devices       : {trusted_count}")
    print(f"Pending Review        : {pending_count}")
    print(f"Unknown Devices       : {unknown_count}")
    print(f"Open TCP Services     : {total_open_ports}")
    print(f"Newly Visible         : {len(new_devices)}")
    print(f"No Longer Visible     : {len(missing_devices)}")
    print(f"Highest Device Risk   : {highest_device_risk}")
    print(f"Overall Risk Level    : {overall_risk}")

    print()

    if overall_risk == "LOW":
        print("Recommendation        : No immediate action required.")

    elif overall_risk == "MEDIUM":
        print("Recommendation        : Review recent network changes.")

    elif overall_risk == "HIGH":
        print("Recommendation        : Investigate high-risk devices.")

    else:
        print("Recommendation        : Investigate immediately.")