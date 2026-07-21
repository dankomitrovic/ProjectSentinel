"""
Project Sentinel console reporting.

This module controls how scan results and security information appear
in the terminal.
"""


def display_banner():
    """
    Display the Project Sentinel heading.
    """

    print()
    print("=" * 60)
    print("PROJECT SENTINEL")
    print("Network Discovery and Trusted Device Monitoring")
    print("=" * 60)


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

        print(f"Name       : {device['friendly_name']}")
        print(f"IP Address : {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")
        print(f"Status     : {device['status']}")

        if device["status"] == "TRUSTED":
            print(f"Owner      : {device['owner']}")
            print(f"Type       : {device['device_type']}")
            print(f"Trust Level: {device['trust_level']}")
            print(f"Notes      : {device['notes']}")

        elif device["status"] == "PENDING":
            print("Risk       : Review Required")
            print("Action     : Awaiting manual approval")

        device_number += 1


def display_changes(new_devices, missing_devices):
    """
    Display changes detected since the previous scan.
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
        print(f"IP Address : {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")

    for device in missing_devices:
        print()
        print("DEVICE NO LONGER VISIBLE")
        print(f"Previous IP: {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")


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