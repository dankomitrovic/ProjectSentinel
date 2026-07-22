"""
Project Sentinel detection engine.

This module compares the previous network state with the current state.
It does not scan the network and does not write files.
"""


def compare_scans(previous_devices, current_devices):
    """
    Compare the previous and current scans using MAC addresses.

    Returns:
        Two lists:
        - newly visible devices
        - devices no longer visible
    """

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

    return new_devices, missing_devices