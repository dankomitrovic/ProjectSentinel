"""
Project Sentinel detection engine.

This module compares the previous network state with the current state.
It does not scan the network and does not write files.
"""

from logger import log_debug, log_info


def compare_scans(previous_devices, current_devices):
    """
    Compare the previous and current scans using MAC addresses.

    Returns:
        Two lists:
        - newly visible devices
        - devices no longer visible
    """

    log_debug("Comparing previous and current network state")
    log_debug(f"Previous scan contained {len(previous_devices)} device(s)")
    log_debug(f"Current scan contains {len(current_devices)} device(s)")

    # Index each scan by MAC address so lookups become
    # fast dictionary operations instead of repeatedly
    # searching through lists.
    previous_by_mac = {
        device["mac_address"]: device
        for device in previous_devices
    }

    current_by_mac = {
        device["mac_address"]: device
        for device in current_devices
    }

    previous_mac_addresses = set(previous_by_mac.keys())
    current_mac_addresses = set(current_by_mac.keys())

    new_mac_addresses = (
        current_mac_addresses - previous_mac_addresses
    )

    missing_mac_addresses = (
        previous_mac_addresses - current_mac_addresses
    )

    new_devices = [
        current_by_mac[mac_address]
        for mac_address in new_mac_addresses
    ]

    missing_devices = [
        previous_by_mac[mac_address]
        for mac_address in missing_mac_addresses
    ]

    for device in new_devices:
        log_info(
            f"New device detected: "
            f"{device['ip_address']} "
            f"({device['mac_address']})"
        )

    for device in missing_devices:
        log_info(
            f"Device no longer visible: "
            f"{device['ip_address']} "
            f"({device['mac_address']})"
        )

    log_debug(
        f"Comparison complete: "
        f"{len(new_devices)} new, "
        f"{len(missing_devices)} missing"
    )

    return new_devices, missing_devices